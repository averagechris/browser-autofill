import test from 'node:test';
import assert from 'node:assert/strict';

globalThis.self = globalThis;
const { NativeClient } = await import('../hardened/native.js');
const nacl = globalThis.nacl;
const encode = bytes => Buffer.from(bytes).toString('base64');
const decode = value => new Uint8Array(Buffer.from(value, 'base64'));
const text = new TextEncoder();
const utf8 = new TextDecoder();
const target = 'https://accounts.example.com/login?next=%2Faccount';
const status = {
  serverVersionInfo: 'synthetic-only',
  databases: [{ uuid: 'dummy-db', nickName: 'Dummy', autoFillEnabled: true, locked: false }],
  serverSettings: { supportsCreateNew: true },
};
const credential = {
  uuid: 'dummy-node', databaseId: 'dummy-db', title: 'Dummy', username: 'dummy-user',
  password: 'dummy-password', url: target,
  totp: 'otpauth://totp/dummy?secret=TEST', notes: 'strip this', customFields: [],
};

function fixture() {
  const state = { key: nacl.box.keyPair(), requests: [], response: null, mutate: response => response };
  state.respond = (host, request) => {
    assert.equal(host, 'com.markmcguill.strongbox');
    state.requests.push(structuredClone(request));
    let value;
    if (request.messageType === 0) {
      assert.equal(request.message, '');
      assert.equal(request.nonce, '');
      value = state.response ?? status;
    } else {
      assert.equal(request.messageType, 2);
      const opened = nacl.box.open(decode(request.message), decode(request.nonce), decode(request.clientPublicKey), state.key.secretKey);
      assert.ok(opened);
      state.payload = JSON.parse(utf8.decode(opened));
      value = state.response ?? { results: [credential], unlockedDatabaseCount: 1 };
    }
    const nonce = nacl.randomBytes(24);
    const message = nacl.box(text.encode(JSON.stringify(value)), nonce, decode(request.clientPublicKey), state.key.secretKey);
    return state.mutate({ success: true, serverPublicKey: encode(state.key.publicKey), nonce: encode(nonce), message: encode(message) });
  };
  state.client = new NativeClient(state.respond);
  return state;
}

test('only status and current-origin, fixed-bounds URL lookup are sent; excess fields are stripped', async () => {
  const f = fixture();
  assert.deepEqual(await f.client.status(), status);
  const response = await f.client.credentialsForUrl(target);
  assert.deepEqual(f.payload, { url: target, skip: 0, take: 24, subdomainMatching: true });
  assert.deepEqual(response.results[0], {
    uuid: credential.uuid, databaseId: credential.databaseId, title: credential.title,
    username: credential.username, password: credential.password, url: credential.url,
  });
  assert.deepEqual(f.requests.map(request => request.messageType), [0, 2]);
  assert.ok(!('totp' in response.results[0]));
});

test('URL lookup requires an explicit successful status handshake', async () => {
  const f = fixture();
  await assert.rejects(f.client.credentialsForUrl(target), /status required/);
  assert.equal(f.requests.length, 0);
});

test('rejects unsafe and noncanonical URLs without sending a lookup', async () => {
  const f = fixture();
  await f.client.status();
  for (const url of ['http://example.com/', 'https://user:pass@example.com/', 'file:///tmp/test',
    'https://EXAMPLE.com/', 'https://example.com/a/../b']) {
    await assert.rejects(f.client.credentialsForUrl(url));
  }
  assert.equal(f.requests.length, 1);
  await f.client.credentialsForUrl('https://example.com');
  assert.equal(f.payload.url, 'https://example.com');
  await f.client.credentialsForUrl('http://127.0.0.1:57839/');
  assert.equal(f.payload.url, 'http://127.0.0.1:57839/');
});

test('rejects malformed Base64 and invalid decoded lengths before decrypting', async () => {
  for (const [field, value] of [
    ['serverPublicKey', '!invalid!'], ['serverPublicKey', encode(new Uint8Array(31))],
    ['nonce', encode(new Uint8Array(23))], ['nonce', encode(new Uint8Array(25))],
    ['message', encode(new Uint8Array(15))], ['message', 'AB=='],
  ]) {
    const f = fixture();
    f.mutate = response => ({ ...response, [field]: value });
    await assert.rejects(f.client.status(), /Native request failed/);
    await assert.rejects(f.client.credentialsForUrl(target), /status required/);
  }
});

test('rejects authenticated payload tampering and clears the session', async () => {
  const f = fixture();
  await f.client.status();
  f.mutate = response => {
    const ciphertext = decode(response.message);
    ciphertext[0] ^= 1;
    return { ...response, message: encode(ciphertext) };
  };
  await assert.rejects(f.client.credentialsForUrl(target), /Native request failed/);
  await assert.rejects(f.client.credentialsForUrl(target), /status required/);
});

test('pins the first successfully decrypted key and requires new status after a key change', async () => {
  const f = fixture();
  await f.client.status();
  f.mutate = response => {
    const changed = nacl.box.keyPair();
    const nonce = nacl.randomBytes(24);
    const request = f.requests.at(-1);
    const message = nacl.box(text.encode(JSON.stringify({ results: [], unlockedDatabaseCount: 0 })), nonce,
      decode(request.clientPublicKey), changed.secretKey);
    return { success: true, serverPublicKey: encode(changed.publicKey), nonce: encode(nonce), message: encode(message) };
  };
  await assert.rejects(f.client.credentialsForUrl(target), /Native request failed/);
  await assert.rejects(f.client.credentialsForUrl(target), /status required/);
  f.mutate = response => response;
  f.key = nacl.box.keyPair();
  assert.deepEqual(await f.client.status(), status);
});

test('rejects a changed server key on later status calls too', async () => {
  const f = fixture();
  await f.client.status();
  f.key = nacl.box.keyPair();
  await assert.rejects(f.client.status(), /Native request failed/);
});

test('validates status and credential schemas and total response bounds', async () => {
  for (const value of [
    { ...status, databases: [{ ...status.databases[0], locked: 'false' }] },
    { ...status, serverSettings: [] }, { ...status, databases: new Array(257).fill(status.databases[0]) },
    [],
  ]) {
    const f = fixture(); f.response = value;
    await assert.rejects(f.client.status(), /Native request failed/);
  }
  for (const value of [
    { results: [{ ...credential, password: 123 }], unlockedDatabaseCount: 1 },
    { results: new Array(25).fill(credential), unlockedDatabaseCount: 1 },
    { results: [], unlockedDatabaseCount: -1 },
  ]) {
    const f = fixture(); await f.client.status(); f.response = value;
    await assert.rejects(f.client.credentialsForUrl(target), /Native request failed/);
  }
  const f = fixture();
  f.mutate = response => ({ ...response, excess: 'x'.repeat(1024 * 1024) });
  await assert.rejects(f.client.status(), /Native request failed/);
});

test('clear discards a pending response and next status uses a fresh client key', async () => {
  const f = fixture();
  let release;
  let request;
  const client = new NativeClient(async (host, value) => {
    request = value;
    await new Promise(resolve => { release = resolve; });
    return f.respond(host, value);
  });
  const pending = client.status();
  await Promise.resolve();
  const publicKey = request.clientPublicKey;
  client.clear();
  release();
  await assert.rejects(pending, /Native request failed/);
  const next = client.status();
  await Promise.resolve();
  assert.notEqual(request.clientPublicKey, publicKey);
  release();
  await next;
});

test('timeout and concurrency remain bounded until the underlying native call settles', async () => {
  const f = fixture();
  let release;
  let calls = 0;
  const client = new NativeClient(async (host, request) => {
    calls++;
    await new Promise(resolve => { release = resolve; });
    return f.respond(host, request);
  }, { timeoutMs: 5 });
  const pending = client.status();
  await assert.rejects(client.status(), /already pending/);
  await assert.rejects(pending, /timed out/);
  await assert.rejects(client.status(), /already pending/);
  assert.equal(calls, 1);
  release();
  await new Promise(resolve => setTimeout(resolve, 0));
});

test('transport errors and unsuccessful native envelopes clear the session', async () => {
  const client = new NativeClient(() => { throw new Error('synthetic transport error'); });
  await assert.rejects(client.status(), /Native request failed/);
  const f = fixture();
  await f.client.status();
  f.mutate = () => ({ success: false, errorMessage: 'synthetic failure' });
  await assert.rejects(f.client.credentialsForUrl(target), /Native request failed/);
  await assert.rejects(f.client.credentialsForUrl(target), /status required/);
});
