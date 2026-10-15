#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const readline = require('node:readline');
const { spawnSync } = require('node:child_process');

const DEFAULT_HOME = process.platform === 'win32'
  ? path.join(process.env.LOCALAPPDATA || os.homedir(), 'vault-cli')
  : path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share'), 'vault-cli');
const DATA_HOME = path.resolve(process.env.VAULT_HOME || DEFAULT_HOME);
const PROFILES_DIR = path.join(DATA_HOME, 'profiles');
const STATE_HOME = process.platform === 'win32'
  ? path.join(process.env.LOCALAPPDATA || os.homedir(), 'vault-cli')
  : path.join(process.env.XDG_STATE_HOME || path.join(os.homedir(), '.local', 'state'), 'vault-cli');
const ACTIVE_FILE = path.join(STATE_HOME, 'current-profile');

function fail(message, code = 1) {
  console.error(`vault: ${message}`);
  process.exitCode = code;
}
function validName(name) {
  return typeof name === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(name);
}
function validKey(key) {
  return typeof key === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(key);
}
function profilePath(name, profilesDir = PROFILES_DIR) {
  if (!validName(name)) throw new Error('profile 名称只能包含字母、数字、下划线和连字符');
  return path.join(profilesDir, `${name}.json`);
}
function ensurePrivateDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') {
    const st = fs.statSync(dir);
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
      throw new Error(`目录所有者不是当前用户：${dir}`);
    }
    fs.chmodSync(dir, 0o700);
  }
}
function assertPrivateFile(file) {
  const st = fs.lstatSync(file);
  if (st.isSymbolicLink() || !st.isFile()) throw new Error('配置文件必须是普通文件，不能是符号链接');
  if (process.platform !== 'win32') {
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw new Error('配置文件不属于当前操作系统用户');
    if ((st.mode & 0o077) !== 0) throw new Error('配置文件权限过宽；请设置为 chmod 600');
  }
}
function getWindowsUser() {
  const domain = process.env.USERDOMAIN;
  const username = process.env.USERNAME;
  if (domain && username) return `${domain}\\${username}`;
  return username || os.userInfo().username;
}
function isWindowsAdministrator() {
  if (process.platform !== 'win32') return true;
  const script = "$p = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }";
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, encoding: 'utf8' });
  return result.status === 0;
}
function quoteWindowsArg(value) {
  const s = String(value);
  if (s.length && !(/[\s"]/.test(s))) return s;
  return JSON.stringify(s);
}
function elevateWindows(argv, targetUser = getWindowsUser()) {
  const nodeExe = process.execPath;
  const scriptPath = path.resolve(process.argv[1]);
  const forwardArgs = [
    scriptPath,
    ...argv,
    '--grant-user', targetUser,
    '--vault-home', DATA_HOME,
    '--elevated-child'
  ];
  const psQuote = v => `'${String(v).replace(/'/g, "''")}'`;
  const argListStr = forwardArgs.map(quoteWindowsArg).join(' ');
  const psCommand = `$p = Start-Process -FilePath ${psQuote(nodeExe)} -ArgumentList ${psQuote(argListStr)} -Verb RunAs -Wait -PassThru; exit $p.ExitCode`;
  const result = spawnSync('powershell.exe', ['-NoProfile', '-Command', psCommand], { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error('需要管理员权限；UAC 提权未能启动、已取消或切换失败');
  }
}
function requireWindowsAdministrator(argv) {
  if (process.platform !== 'win32') return false;
  if (argv.includes('--elevated-child')) return false;
  const [command, ...args] = argv;
  // Only `vault profile <name>` switches profiles and prompts for UAC.
  // Status/list/init and all read/write/help commands must not trigger UAC.
  const needsAdmin = command === 'profile' && args.length === 1 && validName(args[0]) && !['list', '--list', 'init', '--status'].includes(args[0]);
  if (!needsAdmin || isWindowsAdministrator()) return false;
  elevateWindows(argv);
  return true;
}
function secureWindowsUserFileAcl(file, user = getWindowsUser()) {
  if (process.platform !== 'win32') return;
  const grants = ['*S-1-5-32-544:F', '*S-1-5-18:F'];
  if (user) grants.push(`${user}:F`);
  spawnSync('icacls.exe', [file, '/inheritance:r', '/grant:r', ...grants], { encoding: 'utf8', windowsHide: true });
}
function lockWindowsProfileFile(file, user = getWindowsUser()) {
  if (process.platform !== 'win32') return;
  if (user) {
    spawnSync('icacls.exe', [file, '/remove:g', user, '*S-1-5-32-545'], { encoding: 'utf8', windowsHide: true });
  }
  spawnSync('icacls.exe', [file, '/inheritance:r', '/grant:r', '*S-1-5-32-544:F', '*S-1-5-18:F'], { encoding: 'utf8', windowsHide: true });
}
function syncWindowsProfileAcls(activeName, targetUser = getWindowsUser(), profilesDir = PROFILES_DIR) {
  if (process.platform !== 'win32') return;
  if (!targetUser) return;
  ensurePrivateDir(profilesDir);
  // Ensure profile directory allows Administrators, SYSTEM, and the target user to list & create files
  spawnSync('icacls.exe', [
    profilesDir,
    '/inheritance:r',
    '/grant:r',
    '*S-1-5-32-544:(OI)(CI)F',
    '*S-1-5-18:(OI)(CI)F',
    `${targetUser}:(OI)(CI)F`
  ], { encoding: 'utf8', windowsHide: true });

  if (!fs.existsSync(profilesDir)) return;
  for (const entry of fs.readdirSync(profilesDir, { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith('.json')) {
      const pName = entry.name.slice(0, -5);
      const filePath = path.join(profilesDir, entry.name);
      if (pName === activeName) {
        // Active profile: unlocked for target user
        spawnSync('icacls.exe', [
          filePath,
          '/inheritance:r',
          '/grant:r',
          '*S-1-5-32-544:F',
          '*S-1-5-18:F',
          `${targetUser}:F`
        ], { encoding: 'utf8', windowsHide: true });
      } else {
        // Inactive profiles: locked to Admin & SYSTEM only (explicitly remove user and common groups)
        spawnSync('icacls.exe', [
          filePath,
          '/remove:g',
          targetUser,
          '*S-1-5-32-545'
        ], { encoding: 'utf8', windowsHide: true });
        spawnSync('icacls.exe', [
          filePath,
          '/inheritance:r',
          '/grant:r',
          '*S-1-5-32-544:F',
          '*S-1-5-18:F'
        ], { encoding: 'utf8', windowsHide: true });
        spawnSync('icacls.exe', [filePath, '/setowner', '*S-1-5-32-544'], { encoding: 'utf8', windowsHide: true });
      }
    }
  }
}
function readProfile(name, profilesDir = PROFILES_DIR) {
  const file = profilePath(name, profilesDir);
  assertPrivateFile(file);
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (e.code === 'EPERM' || e.code === 'EACCES') {
      throw new Error(`无权访问 profile "${name}"；该 profile 未激活或需要管理员权限授权，请运行 vault profile ${name}`);
    }
    throw e;
  }
  const data = JSON.parse(raw);
  if (data.version !== 1 || !data.values || typeof data.values !== 'object' || !data.auth) {
    throw new Error(`profile 文件格式无效：${name}`);
  }
  return data;
}
function writePrivateText(file, text) {
  ensurePrivateDir(path.dirname(file));
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  let fd;
  try {
    fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    fs.writeFileSync(fd, text, 'utf8'); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    if (process.platform !== 'win32') fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, file);
    if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
    else secureWindowsUserFileAcl(file);
  } finally { if (fd !== undefined) fs.closeSync(fd); try { fs.unlinkSync(tmp); } catch {} }
}
function writeJsonPrivate(file, data) {
  ensurePrivateDir(path.dirname(file));
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  let fd;
  try {
    fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    fs.writeFileSync(fd, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd); fd = undefined;
    if (process.platform !== 'win32') fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, file);
    if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
    else secureWindowsUserFileAcl(file);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(tmp); } catch {}
  }
}
let lineInterface;
let pipedLines;
let pipedIndex = 0;
async function prompt(question, { hidden = false } = {}) {
  if (hidden && process.stdin.isTTY && typeof process.stdin.setRawMode === 'function') {
    return new Promise((resolve, reject) => {
      const stdin = process.stdin;
      const wasRaw = stdin.isRaw;
      let value = '';
      process.stderr.write(question);
      stdin.setRawMode(true); stdin.resume();
      const onData = chunk => {
        const s = chunk.toString('utf8');
        if (s === '\u0003') { cleanup(); reject(new Error('已取消')); return; }
        if (s === '\r' || s === '\n') { cleanup(); process.stderr.write('\n'); resolve(value); return; }
        if (s === '\u007f' || s === '\b') { value = value.slice(0, -1); return; }
        if (s >= ' ') value += s;
      };
      const cleanup = () => { stdin.removeListener('data', onData); stdin.setRawMode(wasRaw); stdin.pause(); };
      stdin.on('data', onData);
    });
  }
  if (!process.stdin.isTTY) {
    process.stderr.write(question);
    if (!pipedLines) {
      const chunks = [];
      for await (const chunk of process.stdin) chunks.push(chunk);
      pipedLines = Buffer.concat(chunks).toString('utf8').split(/\r?\n/);
    }
    return pipedLines[pipedIndex++] ?? '';
  }
  if (!lineInterface) lineInterface = readline.createInterface({ input: process.stdin, output: process.stderr, terminal: true });
  return new Promise(resolve => lineInterface.question(question, answer => resolve(answer)));
}
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, auth) {
  const candidate = crypto.scryptSync(password, auth.salt, 64);
  const expected = Buffer.from(auth.hash, 'hex');
  return expected.length === candidate.length && crypto.timingSafeEqual(candidate, expected);
}
function activeProfile() {
  try {
    const name = fs.readFileSync(ACTIVE_FILE, 'utf8').trim();
    return validName(name) ? name : null;
  } catch { return null; }
}
function listProfiles() {
  try {
    return fs.readdirSync(PROFILES_DIR).filter(f => f.endsWith('.json')).map(f => f.slice(0, -5)).filter(validName).sort();
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    if (process.platform === 'win32' && (e.code === 'EPERM' || e.code === 'EACCES')) {
      throw new Error(`无法读取 profiles 目录（目录权限被旧版本锁死）：${PROFILES_DIR}\n请在 PowerShell 中执行以下命令恢复权限：\n  Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -Command icacls \"$env:LOCALAPPDATA\\vault-cli\" /reset /t'`);
    }
    throw e;
  }
}
async function readStdinValue() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const value = Buffer.concat(chunks).toString('utf8');
  return value.endsWith('\n') ? value.slice(0, -1).replace(/\r$/, '') : value;
}

async function main(argv) {
  let grantUser = getWindowsUser();
  let isElevatedChild = false;
  const cleanArgs = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--elevated-child') {
      isElevatedChild = true;
    } else if (argv[i] === '--grant-user' && i + 1 < argv.length) {
      grantUser = argv[++i];
    } else if (argv[i] === '--vault-home' && i + 1 < argv.length) {
      // already resolved or can override
      i++;
    } else {
      cleanArgs.push(argv[i]);
    }
  }

  const [command, ...args] = cleanArgs;
  try {
    if (!command || ['help', '--help', '-h'].includes(command)) return usage();
    if (requireWindowsAdministrator(cleanArgs)) {
      console.log(`当前 profile：${cleanArgs[1]}`);
      return;
    }
    if (command === 'profile') {
      if (args.length === 0 || args[0] === '--status') {
        console.log(activeProfile() || '(未选择 profile)');
        return;
      }
      if (args[0] === 'list' || args[0] === '--list') {
        const active = activeProfile();
        for (const name of listProfiles()) console.log(`${name === active ? '* ' : '  '}${name}`);
        return;
      }
      if (args[0] === 'init') {
        const name = args[1];
        if (!validName(name)) throw new Error('用法：vault profile init <name>');
        ensurePrivateDir(PROFILES_DIR);
        const file = profilePath(name);
        if (fs.existsSync(file)) throw new Error(`profile 已存在：${name}`);
        const p1 = await prompt('设置此 profile 的切换密码：', { hidden: true });
        if (p1.length < 8) throw new Error('密码至少需要 8 个字符');
        const p2 = await prompt('再次输入密码：', { hidden: true });
        if (p1 !== p2) throw new Error('两次密码不一致');
        writeJsonPrivate(file, { version: 1, auth: hashPassword(p1), values: {} });
        if (process.platform === 'win32') {
          lockWindowsProfileFile(file);
        }
        console.log(`已创建 profile：${name}`);
        return;
      }
      if (args.length !== 1 || !validName(args[0])) throw new Error('用法：vault profile [list|init <name>|<name>]');
      const name = args[0];
      const data = readProfile(name); // OS permissions are checked before asking for a password.
      const password = await prompt(`切换到 ${name}，请输入密码：`, { hidden: true });
      if (!verifyPassword(password, data.auth)) {
        if (isElevatedChild) {
          console.error('vault: 密码错误');
          await new Promise(r => setTimeout(r, 1500));
        }
        throw new Error('密码错误');
      }
      if (process.platform === 'win32') {
        syncWindowsProfileAcls(name, grantUser, PROFILES_DIR);
      }
      // Current profile is a non-secret per-user state file.
      writePrivateText(ACTIVE_FILE, `${name}\n`);
      console.log(`当前 profile：${name}`);
      return;
    }
    if (command === 'read') {
      const key = args[0];
      if (args.length !== 1 || !validKey(key)) throw new Error('用法：vault read <KEY>');
      const name = activeProfile();
      if (!name) throw new Error('尚未选择 profile；请先运行 vault profile <name>');
      const data = readProfile(name);
      if (!Object.prototype.hasOwnProperty.call(data.values, key)) throw new Error(`键不存在：${key}`);
      const value = data.values[key];
      if (typeof value !== 'string') throw new Error(`键值格式无效：${key}`);
      process.stdout.write(`${value}\n`);
      return;
    }
    if (command === 'write') {
      const key = args[0];
      if (!validKey(key) || args.length > 2) throw new Error('用法：vault write <KEY> [VALUE|--stdin]');
      const name = activeProfile();
      if (!name) throw new Error('尚未选择 profile；请先运行 vault profile <name>');
      const data = readProfile(name);
      const value = args.length === 2 && args[1] === '--stdin' ? await readStdinValue() : args.length === 2 ? args[1] : args.length === 1 ? await prompt(`输入 ${key} 的值（输入内容不会回显）：`, { hidden: true }) : (() => { throw new Error('用法：vault write <KEY> [VALUE|--stdin]'); })();
      data.values[key] = value;
      writeJsonPrivate(profilePath(name), data);
      console.log(`已写入 ${name}.${key}`);
      return;
    }
    throw new Error(`未知命令：${command}`);
  } catch (e) { fail(e.message || String(e)); }
}
function usage() {
  console.log(`vault — 本地 JSON profile 配置工具\n\n命令：\n  vault profile                  查看当前 profile\n  vault profile list             列出当前操作系统账户可访问的 profile\n  vault profile init <name>      创建 profile 并设置切换密码\n  vault profile <name>           验证密码并切换 profile\n  vault read <KEY>               读取当前 profile 的值\n  vault write <KEY> [VALUE|--stdin] 写入当前 profile；省略值时安全提示输入\n\n存储目录：${DATA_HOME}\n可通过 VAULT_HOME 覆盖。`);
}

if (require.main === module) main(process.argv.slice(2)).finally(() => { if (lineInterface) lineInterface.close(); });
module.exports = { validName, validKey, hashPassword, verifyPassword, profilePath, readProfile, writeJsonPrivate, writePrivateText, isWindowsAdministrator, syncWindowsProfileAcls };
