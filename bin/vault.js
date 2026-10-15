#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const readline = require('node:readline');

const DEFAULT_HOME = process.platform === 'win32'
  ? path.join(process.env.LOCALAPPDATA || os.homedir(), 'vault-cli')
  : path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share'), 'vault-cli');
const DATA_HOME = path.resolve(process.env.VAULT_HOME || DEFAULT_HOME);
const PROFILES_DIR = path.join(DATA_HOME, 'profiles');

function getSessionDir() {
  if (process.env.VAULT_HOME) {
    return path.join(DATA_HOME, 'state');
  }
  if (process.platform === 'linux' && fs.existsSync('/dev/shm')) {
    const uid = typeof process.getuid === 'function' ? process.getuid() : 'default';
    return path.join('/dev/shm', `vault-cli-${uid}`);
  }
  if (process.env.XDG_RUNTIME_DIR) {
    return path.join(process.env.XDG_RUNTIME_DIR, 'vault-cli');
  }
  return process.platform === 'win32'
    ? path.join(process.env.LOCALAPPDATA || os.homedir(), 'vault-cli')
    : path.join(process.env.XDG_STATE_HOME || path.join(os.homedir(), '.local', 'state'), 'vault-cli');
}

const SESSION_DIR = getSessionDir();
const SESSION_FILE = path.join(SESSION_DIR, 'session.json');

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
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
      throw new Error('配置文件不属于当前操作系统用户');
    }
    if ((st.mode & 0o077) !== 0) {
      throw new Error('配置文件权限过宽；请设置为 chmod 600');
    }
  }
}

// Key derivation and AES-256-GCM encryption helpers
function deriveKey(password, salt) {
  const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'hex');
  return crypto.scryptSync(password, saltBuf, 32);
}

function encryptPayload(payloadObj, key) {
  const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
  const plaintext = Buffer.from(JSON.stringify(payloadObj), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    data: encrypted.toString('hex')
  };
}

function decryptPayload(encryptedDataHex, key, ivHex, tagHex) {
  const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encryptedDataHex, 'hex')),
    decipher.final()
  ]);
  return JSON.parse(decrypted.toString('utf8'));
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

function writePrivateText(file, text) {
  ensurePrivateDir(path.dirname(file));
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  let fd;
  try {
    fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    fs.writeFileSync(fd, text, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    if (process.platform !== 'win32') fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, file);
    if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(tmp); } catch {}
  }
}

function writeJsonPrivate(file, data) {
  writePrivateText(file, `${JSON.stringify(data, null, 2)}\n`);
}

function readProfileRaw(name, profilesDir = PROFILES_DIR) {
  const file = profilePath(name, profilesDir);
  assertPrivateFile(file);
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (e.code === 'EPERM' || e.code === 'EACCES') {
      throw new Error(`无权访问 profile "${name}"`);
    }
    throw e;
  }
  const data = JSON.parse(raw);
  if (!data || (!data.auth && !data.crypto)) {
    throw new Error(`profile 文件格式无效：${name}`);
  }
  return data;
}

// Session management: stores active profile name and derived AES key (not raw password)
function getActiveSession(sessionFile = SESSION_FILE) {
  try {
    if (!fs.existsSync(sessionFile)) return null;
    assertPrivateFile(sessionFile);
    const session = JSON.parse(fs.readFileSync(sessionFile, 'utf8'));
    if (!session || !validName(session.name) || !session.keyHex || !session.saltHex) {
      return null;
    }
    return session;
  } catch {
    return null;
  }
}

function saveActiveSession(name, keyBuffer, saltHex, sessionFile = SESSION_FILE) {
  writeJsonPrivate(sessionFile, {
    name,
    keyHex: keyBuffer.toString('hex'),
    saltHex,
    createdAt: Date.now()
  });
}

function readProfile(name, profilesDir = PROFILES_DIR, optionalKey = null) {
  const profile = readProfileRaw(name, profilesDir);

  // Backward compatibility: legacy unencrypted profile (version 1)
  if (profile.version === 1 && profile.values && typeof profile.values === 'object') {
    return profile;
  }

  // Version 2 encrypted profile
  if (profile.crypto) {
    let key = optionalKey;
    if (!key) {
      const session = getActiveSession();
      if (session && session.name === name) {
        key = Buffer.from(session.keyHex, 'hex');
      }
    }
    if (!key) {
      throw new Error(`尚未选择 profile "${name}" 或未提供解密密钥；请先运行 vault profile ${name}`);
    }

    try {
      const values = decryptPayload(profile.crypto.data, key, profile.crypto.iv, profile.crypto.tag);
      return {
        ...profile,
        values
      };
    } catch {
      throw new Error(`解密 profile "${name}" 失败；密码错误或会话密钥已失效`);
    }
  }

  throw new Error(`profile 文件格式不支持：${name}`);
}

function writeProfileEncrypted(name, values, key, profilesDir = PROFILES_DIR) {
  const file = profilePath(name, profilesDir);
  let profile;
  try {
    profile = readProfileRaw(name, profilesDir);
  } catch {
    profile = null;
  }

  const salt = profile?.crypto?.salt || crypto.randomBytes(16).toString('hex');
  const enc = encryptPayload(values, key);

  const updatedProfile = {
    version: 2,
    auth: profile?.auth || hashPassword(crypto.randomBytes(32).toString('hex')),
    crypto: {
      salt,
      iv: enc.iv,
      tag: enc.tag,
      data: enc.data
    }
  };

  writeJsonPrivate(file, updatedProfile);
}

function activeProfile() {
  const session = getActiveSession();
  return session ? session.name : null;
}

function listProfiles(profilesDir = PROFILES_DIR) {
  try {
    return fs.readdirSync(profilesDir)
      .filter(f => f.endsWith('.json'))
      .map(f => f.slice(0, -5))
      .filter(validName)
      .sort();
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
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
      stdin.setRawMode(true);
      stdin.resume();
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

async function readStdinValue() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const value = Buffer.concat(chunks).toString('utf8');
  return value.endsWith('\n') ? value.slice(0, -1).replace(/\r$/, '') : value;
}

// Compatibility stubs for Windows/ACL (no longer needed for AES-GCM isolation)
function isWindowsAdministrator() {
  return true;
}
function syncWindowsProfileAcls() {}

async function main(argv) {
  const cleanArgs = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--elevated-child') {
      continue;
    } else if (argv[i] === '--grant-user' && i + 1 < argv.length) {
      i++;
    } else if (argv[i] === '--vault-home' && i + 1 < argv.length) {
      i++;
    } else {
      cleanArgs.push(argv[i]);
    }
  }

  const [command, ...args] = cleanArgs;
  try {
    if (!command || ['help', '--help', '-h'].includes(command)) return usage();

    if (command === 'profile') {
      if (args.length === 0 || args[0] === '--status') {
        console.log(activeProfile() || '(未选择 profile)');
        return;
      }
      if (args[0] === 'list' || args[0] === '--list') {
        const active = activeProfile();
        for (const name of listProfiles()) {
          console.log(`${name === active ? '* ' : '  '}${name}`);
        }
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

        const cryptoSalt = crypto.randomBytes(16).toString('hex');
        const key = deriveKey(p1, cryptoSalt);
        const enc = encryptPayload({}, key);

        const profileData = {
          version: 2,
          auth: hashPassword(p1),
          crypto: {
            salt: cryptoSalt,
            iv: enc.iv,
            tag: enc.tag,
            data: enc.data
          }
        };

        writeJsonPrivate(file, profileData);
        console.log(`已创建 profile：${name}`);
        return;
      }

      if (args.length !== 1 || !validName(args[0])) {
        throw new Error('用法：vault profile [list|init <name>|<name>]');
      }

      const name = args[0];
      const rawProfile = readProfileRaw(name);
      const password = await prompt(`切换到 ${name}，请输入密码：`, { hidden: true });

      if (rawProfile.auth && !verifyPassword(password, rawProfile.auth)) {
        throw new Error('密码错误');
      }

      // Handle legacy v1 upgrade or v2 key derivation
      let cryptoSalt = rawProfile.crypto?.salt;
      if (!cryptoSalt) {
        cryptoSalt = crypto.randomBytes(16).toString('hex');
      }
      const derivedKey = deriveKey(password, cryptoSalt);

      // Verify or upgrade legacy profile
      if (rawProfile.version === 1 && rawProfile.values) {
        const enc = encryptPayload(rawProfile.values, derivedKey);
        writeJsonPrivate(profilePath(name), {
          version: 2,
          auth: rawProfile.auth,
          crypto: {
            salt: cryptoSalt,
            iv: enc.iv,
            tag: enc.tag,
            data: enc.data
          }
        });
      } else if (rawProfile.crypto) {
        // Double check decryption
        try {
          decryptPayload(rawProfile.crypto.data, derivedKey, rawProfile.crypto.iv, rawProfile.crypto.tag);
        } catch {
          throw new Error('密码错误或数据校验失败');
        }
      }

      saveActiveSession(name, derivedKey, cryptoSalt);
      console.log(`当前 profile：${name}`);
      return;
    }

    if (command === 'read') {
      const key = args[0];
      if (args.length !== 1 || !validKey(key)) throw new Error('用法：vault read <KEY>');
      const name = activeProfile();
      if (!name) throw new Error('尚未选择 profile；请先运行 vault profile <name>');
      const session = getActiveSession();
      if (!session || session.name !== name) {
        throw new Error('会话凭据已失效；请重新运行 vault profile <name>');
      }

      const sessionKey = Buffer.from(session.keyHex, 'hex');
      const data = readProfile(name, PROFILES_DIR, sessionKey);
      if (!Object.prototype.hasOwnProperty.call(data.values, key)) {
        throw new Error(`键不存在：${key}`);
      }
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
      const session = getActiveSession();
      if (!session || session.name !== name) {
        throw new Error('会话凭据已失效；请重新运行 vault profile <name>');
      }

      const sessionKey = Buffer.from(session.keyHex, 'hex');
      const data = readProfile(name, PROFILES_DIR, sessionKey);
      const value = args.length === 2 && args[1] === '--stdin'
        ? await readStdinValue()
        : args.length === 2
          ? args[1]
          : args.length === 1
            ? await prompt(`输入 ${key} 的值（输入内容不会回显）：`, { hidden: true })
            : (() => { throw new Error('用法：vault write <KEY> [VALUE|--stdin]'); })();

      data.values[key] = value;
      writeProfileEncrypted(name, data.values, sessionKey, PROFILES_DIR);
      console.log(`已写入 ${name}.${key}`);
      return;
    }

    throw new Error(`未知命令：${command}`);
  } catch (e) {
    fail(e.message || String(e));
  }
}

function usage() {
  console.log(`vault — 本地加密 profile 配置工具\n\n命令：\n  vault profile                  查看当前 profile\n  vault profile list             列出所有已配置的 profile\n  vault profile init <name>      创建 profile 并设置切换密码\n  vault profile <name>           验证密码并切换 profile（保存临时会话密钥）\n  vault read <KEY>               读取当前 profile 的值\n  vault write <KEY> [VALUE|--stdin] 写入当前 profile；省略值时安全提示输入\n\n存储目录：${DATA_HOME}\n可通过 VAULT_HOME 覆盖。`);
}

if (require.main === module) {
  main(process.argv.slice(2)).finally(() => {
    if (lineInterface) lineInterface.close();
  });
}

module.exports = {
  validName,
  validKey,
  hashPassword,
  verifyPassword,
  profilePath,
  readProfile,
  readProfileRaw,
  writeJsonPrivate,
  writePrivateText,
  writeProfileEncrypted,
  deriveKey,
  encryptPayload,
  decryptPayload,
  getActiveSession,
  saveActiveSession,
  isWindowsAdministrator,
  syncWindowsProfileAcls
};
