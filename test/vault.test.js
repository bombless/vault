'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { validName, validKey, hashPassword, verifyPassword, writeJsonPrivate, readProfile } = require('../bin/vault');

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
test('writes private profile JSON and reads values', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-cli-'));
  try {
    const file = path.join(root, 'profiles', 'agent.json');
    writeJsonPrivate(file, { version: 1, auth: hashPassword('test-password-123'), values: { MODEL: 'test-model' } });
    assert.equal(readProfile('agent', path.dirname(file)).values.MODEL, 'test-model');
    if (process.platform !== 'win32') {
      assert.equal(fs.statSync(file).mode & 0o777, 0o600);
      assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
