'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  validName,
  validKey,
  hashPassword,
  verifyPassword,
  writeJsonPrivate,
  readProfile,
  readProfileRaw,
  writeProfileEncrypted,
  deriveKey,
  encryptPayload,
  decryptPayload,
  saveActiveSession,
  getActiveSession
} = require('../bin/vault');

test('validates profile names and keys', () => {
  assert.equal(validName('agent'), true);
  assert.equal(validName('../prod'), false);
  assert.equal(validKey('FEISHU_APP_ID'), true);
  assert.equal(validKey('../secret'), false);
});

test('password hashes verify without storing plaintext', () => {
  const auth = hashPassword('a-long-test-password');
  assert.equal(verifyPassword('a-long-test-password', auth), true);
  assert.equal(verifyPassword('wrong-password', auth), false);
  assert.equal(JSON.stringify(auth).includes('a-long-test-password'), false);
});

test('AES-256-GCM encrypts and decrypts payload correctly', () => {
  const salt = crypto.randomBytes(16);
  const password = 'my-super-secret-password';
  const key = deriveKey(password, salt);
  const payload = { API_KEY: 'sk-123456', MODEL: 'gpt-4o' };

  const encrypted = encryptPayload(payload, key);
  assert.ok(encrypted.iv);
  assert.ok(encrypted.tag);
  assert.ok(encrypted.data);

  // Decrypt with correct key
  const decrypted = decryptPayload(encrypted.data, key, encrypted.iv, encrypted.tag);
  assert.deepEqual(decrypted, payload);

  // Decrypt with wrong key should throw AEAD authentication failure
  const wrongKey = deriveKey('wrong-password', salt);
  assert.throws(() => {
    decryptPayload(encrypted.data, wrongKey, encrypted.iv, encrypted.tag);
  });
});

test('session stores derived key rather than plaintext password', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-session-'));
  const sessionFile = path.join(root, 'session.json');
  try {
    const salt = crypto.randomBytes(16).toString('hex');
    const password = 'plain-text-user-password';
    const key = deriveKey(password, salt);

    saveActiveSession('agent', key, salt, sessionFile);

    const saved = JSON.parse(fs.readFileSync(sessionFile, 'utf8'));
    assert.equal(saved.name, 'agent');
    assert.equal(saved.keyHex, key.toString('hex'));
    // Plaintext password must NOT be in the session file
    assert.equal(JSON.stringify(saved).includes(password), false);

    const active = getActiveSession(sessionFile);
    assert.equal(active.name, 'agent');
    assert.equal(active.keyHex, key.toString('hex'));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('isolates inactive profiles: encrypted on disk, accessible only with key', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-crypto-'));
  const profilesDir = path.join(root, 'profiles');
  fs.mkdirSync(profilesDir, { recursive: true });

  try {
    const saltActive = crypto.randomBytes(16).toString('hex');
    const keyActive = deriveKey('password-active', saltActive);
    writeProfileEncrypted('active', { TOKEN: 'active-token' }, keyActive, profilesDir);

    const saltInactive = crypto.randomBytes(16).toString('hex');
    const keyInactive = deriveKey('password-inactive', saltInactive);
    writeProfileEncrypted('inactive', { SECRET: 'top-secret-prod-key' }, keyInactive, profilesDir);

    // Verify on disk: files do not contain plaintext secrets
    const inactiveRaw = fs.readFileSync(path.join(profilesDir, 'inactive.json'), 'utf8');
    assert.equal(inactiveRaw.includes('top-secret-prod-key'), false);
    assert.equal(inactiveRaw.includes('SECRET'), false);

    // Active profile readable with active key
    const activeData = readProfile('active', profilesDir, keyActive);
    assert.equal(activeData.values.TOKEN, 'active-token');

    // Trying to read inactive profile with active key or without key must fail
    assert.throws(() => {
      readProfile('inactive', profilesDir, keyActive);
    }, /解密 profile "inactive" 失败/);

    assert.throws(() => {
      readProfile('inactive', profilesDir);
    }, /尚未选择 profile "inactive"/);

    // Inactive profile readable with its own key
    const inactiveData = readProfile('inactive', profilesDir, keyInactive);
    assert.equal(inactiveData.values.SECRET, 'top-secret-prod-key');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('backward compatibility: reads legacy version 1 profile', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-v1-'));
  const profilesDir = path.join(root, 'profiles');
  fs.mkdirSync(profilesDir, { recursive: true });
  try {
    const file = path.join(profilesDir, 'legacy.json');
    writeJsonPrivate(file, { version: 1, auth: hashPassword('pwd'), values: { OLD_KEY: 'old-value' } });
    const profile = readProfile('legacy', profilesDir);
    assert.equal(profile.values.OLD_KEY, 'old-value');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('CLI end-to-end lifecycle: init, switch, write, read, and cross-platform isolation', () => {
  const { spawnSync } = require('node:child_process');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-cli-e2e-'));
  const scriptPath = path.resolve(__dirname, '../bin/vault.js');

  function run(args, input = '') {
    return spawnSync(process.execPath, [scriptPath, ...args], {
      input,
      env: { ...process.env, VAULT_HOME: root },
      encoding: 'utf8'
    });
  }

  try {
    // 1. init profiles
    const init1 = run(['profile', 'init', 'agent'], 'pass-agent-123\npass-agent-123\n');
    assert.equal(init1.status, 0);

    const init2 = run(['profile', 'init', 'prod'], 'pass-prod-456\npass-prod-456\n');
    assert.equal(init2.status, 0);

    // 2. switch to agent
    const switchRes = run(['profile', 'agent'], 'pass-agent-123\n');
    assert.equal(switchRes.status, 0);
    assert.match(switchRes.stdout, /当前 profile：agent/);

    // 3. write and read in agent
    const writeRes = run(['write', 'API_KEY', 'sk-agent-111']);
    assert.equal(writeRes.status, 0);

    const readRes = run(['read', 'API_KEY']);
    assert.equal(readRes.status, 0);
    assert.equal(readRes.stdout.trim(), 'sk-agent-111');

    // 4. verify prod profile is encrypted on disk and cannot be read without switching
    const prodFile = fs.readFileSync(path.join(root, 'profiles', 'prod.json'), 'utf8');
    const prodObj = JSON.parse(prodFile);
    assert.equal(prodObj.version, 2);
    assert.ok(prodObj.crypto && prodObj.crypto.data);
    assert.equal(prodFile.includes('sk-agent-111'), false);

    // 5. switch to prod with wrong password fails
    const badSwitch = run(['profile', 'prod'], 'wrong-password\n');
    assert.notEqual(badSwitch.status, 0);

    // 6. switch to prod with correct password
    const goodSwitch = run(['profile', 'prod'], 'pass-prod-456\n');
    assert.equal(goodSwitch.status, 0);
    assert.match(goodSwitch.stdout, /当前 profile：prod/);

    // 7. in prod, agent's key does not exist
    const readOld = run(['read', 'API_KEY']);
    assert.notEqual(readOld.status, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
