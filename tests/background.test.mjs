import test from 'node:test';
import assert from 'node:assert/strict';
globalThis.self = globalThis;
const { BackgroundController } = await import('../hardened/background.js');

const status = () => ({ serverVersionInfo: 'fixture-1', serverSettings: {}, databases: [{ uuid: 'private-db', nickName: 'PRIVATE DATABASE LABEL', autoFillEnabled: true, locked: false }] });
const credential = (extra = {}) => ({ databaseId: 'private-db', title: 'Fixture login', username: 'fixture-user', password: 'SYNTHETIC SECRET', url: 'https://bank.example/login', totp: 'PRIVATE OTP SEED', notes: 'PRIVATE NOTES', ...extra });
function fixture() {
  const sender = { id: 'fixture-id', url: 'chrome-extension://fixture-id/popup.html' };
  let doc = { tabId: 4, url: 'https://bank.example/login', origin: 'https://bank.example', host: 'bank.example', documentId: 'document-one' };
  let clock = 100;
  let sequence = 0;
  const calls = { status: 0, lookup: 0, fills: [], cleared: 0 };
  const native = {
    clear: () => { calls.cleared += 1; },
    status: async () => { calls.status += 1; return status(); },
    credentialsForUrl: async origin => { assert.equal(origin, 'https://bank.example'); calls.lookup += 1; return { results: [credential(), credential({ url: 'https://other.example/login' })], unlockedDatabaseCount: 1 }; },
  };
  const api = {
    runtime: { id: 'fixture-id', getURL: path => `chrome-extension://fixture-id/${path}` },
    tabs: { query: async () => [{ id: doc.tabId }] },
    scripting: { executeScript: async options => {
      if (options.args) {
        calls.fills.push(options);
        return [{ documentId: doc.documentId, frameId: 0, result: { filled: true } }];
      }
      return [{ documentId: doc.documentId, frameId: 0, result: { url: doc.url, origin: doc.origin, host: doc.host } }];
    } },
  };
  const controller = new BackgroundController(api, native, { now: () => clock, token: () => `token-${++sequence}`, schedule: () => 1, cancel: () => {} });
  return { controller, sender, native, calls, api, setDoc: next => { doc = { ...doc, ...next }; }, setClock: time => { clock = time; } };
}

test('only the exact extension popup can perform operations; page context does not fetch native data', async () => {
  const f = fixture();
  for (const sender of [{ ...f.sender, tab: { id: 4 } }, { ...f.sender, url: 'https://attacker.example/' }, { ...f.sender, id: 'other-id' }, { ...f.sender, url: f.sender.url + '?spoof=1' }]) {
    assert.equal((await f.controller.handle({ type: 'lookup' }, sender)).ok, false);
  }
  const result = await f.controller.handle({ type: 'context' }, f.sender);
  assert.equal(result.context.documentId, 'document-one');
  assert.equal(f.calls.status, 0);
  assert.equal(f.calls.lookup, 0);
});

test('status and lookup expose only public projections; fill sends only selected fields to one bound document', async () => {
  const f = fixture();
  assert.deepEqual(await f.controller.handle({ type: 'status' }, f.sender), { ok: true, version: 'fixture-1', unlockedCount: 1 });
  const result = await f.controller.handle({ type: 'lookup' }, f.sender);
  assert.deepEqual(result.items, [{ token: 'token-1', title: 'Fixture login', username: 'fixture-user' }]);
  assert.equal(JSON.stringify(result).includes('SYNTHETIC SECRET'), false);
  assert.equal(JSON.stringify([...f.controller.entries.values()]).includes('PRIVATE'), false);
  assert.equal(JSON.stringify(result).includes('private-db'), false);
  f.controller.onUpdated(99, { status: 'loading' });
  assert.deepEqual(await f.controller.handle({ type: 'fill', token: result.items[0].token }, f.sender), { ok: true });
  assert.deepEqual(f.calls.fills[0].target, { tabId: 4, documentIds: ['document-one'] });
  assert.deepEqual(f.calls.fills[0].args, [{ url: 'https://bank.example/login', origin: 'https://bank.example', username: 'fixture-user', password: 'SYNTHETIC SECRET' }]);
  assert.equal((await f.controller.handle({ type: 'fill', token: 'token-1' }, f.sender)).ok, false);
  assert.equal(f.calls.fills.length, 1);
});

test('navigation during lookup, before fill, expiry and tab events invalidate credentials', async () => {
  for (const mutation of [f => f.setDoc({ documentId: 'replacement' }), f => f.setDoc({ url: 'https://bank.example/other' }), f => f.setDoc({ tabId: 5 }), f => f.setClock(45_101), f => f.controller.onUpdated(4, { status: 'loading' }), f => f.controller.onRemoved(4)]) {
    const f = fixture();
    const result = await f.controller.handle({ type: 'lookup' }, f.sender);
    mutation(f);
    assert.equal((await f.controller.handle({ type: 'fill', token: result.items[0].token }, f.sender)).ok, false);
    assert.equal(f.calls.fills.length, 0);
    assert.equal(f.controller.entries.size, 0);
  }
  const f = fixture();
  f.native.credentialsForUrl = async () => { f.setDoc({ documentId: 'new-document' }); return { results: [credential()], unlockedDatabaseCount: 1 }; };
  assert.equal((await f.controller.handle({ type: 'lookup' }, f.sender)).ok, false);
  assert.equal(f.controller.entries.size, 0);
});

test('HTTP and malformed native data fail closed with generic errors', async () => {
  const f = fixture();
  f.setDoc({ url: 'http://bank.example/login', origin: 'http://bank.example' });
  assert.equal((await f.controller.handle({ type: 'lookup' }, f.sender)).ok, false);
  assert.equal(f.calls.lookup, 0);
  const g = fixture();
  g.native.credentialsForUrl = async () => ({ results: [credential({ password: 'x'.repeat(8193) })], unlockedDatabaseCount: 1 });
  assert.deepEqual(await g.controller.handle({ type: 'lookup' }, g.sender), { ok: false, error: 'Unable to complete this action.' });
  assert.equal(g.controller.entries.size, 0);
});


test('locking, disabling or removing the selected database after lookup prevents fill', async () => {
  for (const databases of [[], [{ uuid: 'private-db', nickName: 'private', autoFillEnabled: true, locked: true }], [{ uuid: 'private-db', nickName: 'private', autoFillEnabled: false, locked: false }], [{ uuid: 'other-db', nickName: 'private', autoFillEnabled: true, locked: false }]]) {
    const f = fixture();
    const result = await f.controller.handle({ type: 'lookup' }, f.sender);
    f.native.status = async () => ({ ...status(), databases });
    assert.deepEqual(await f.controller.handle({ type: 'fill', token: result.items[0].token }, f.sender), { ok: false, error: 'Database is locked or unavailable. Unlock it and look up accounts again.' });
    assert.equal(f.calls.fills.length, 0);
    assert.equal(f.controller.entries.size, 0);
  }
});

test('navigation while the fresh pre-fill database status is pending rejects the cached selection', async () => {
  const f = fixture();
  const result = await f.controller.handle({ type: 'lookup' }, f.sender);
  f.native.status = async () => { f.setDoc({ documentId: 'replacement' }); f.controller.onUpdated(4, { status: 'loading' }); return status(); };
  assert.deepEqual(await f.controller.handle({ type: 'fill', token: result.items[0].token }, f.sender), { ok: false, error: 'The page changed. Look up accounts again.' });
  assert.equal(f.calls.fills.length, 0);
  assert.equal(f.controller.entries.size, 0);
});

test('lookup expiry uses browser timers without binding the controller as their receiver', async t => {
  const f = fixture();
  let scheduled = false;
  let cancelled = false;
  t.mock.method(globalThis, 'setTimeout', function (callback, delay) {
    assert.equal(this, undefined);
    assert.equal(typeof callback, 'function');
    assert.equal(delay, 45_000);
    scheduled = true;
    return 123;
  });
  t.mock.method(globalThis, 'clearTimeout', function (handle) {
    assert.equal(this, undefined);
    assert.equal(handle, 123);
    cancelled = true;
  });
  const controller = new BackgroundController(f.api, f.native);
  assert.equal((await controller.handle({ type: 'lookup' }, f.sender)).ok, true);
  assert.equal(scheduled, true);
  controller.clear();
  assert.equal(cancelled, true);
});

test('fuzzy search keeps site matches usable and requires destination confirmation for a moved account', async () => {
  const f = fixture();
  const matching = await f.controller.handle({ type: 'lookup' }, f.sender);
  f.native.search = async query => ({ results: query ? [] : [
    credential({ uuid: 'archive', title: 'Archive Portal', url: 'https://old.example/' }),
    credential({ uuid: 'other', title: 'Unrelated', url: 'https://old.example/' }),
  ] });
  const search = await f.controller.handle({ type: 'search', query: 'arcp' }, f.sender);
  assert.equal(search.items.length, 1);
  const [account] = search.items;
  assert.equal(account.title, 'Archive Portal');
  assert.equal(account.savedOrigin, 'https://old.example');
  assert.equal(account.requiresConfirmation, true);
  assert.equal(JSON.stringify(search).includes('SYNTHETIC SECRET'), false);
  assert.equal(f.controller.entries.has(matching.items[0].token), true);
  assert.equal((await f.controller.handle({ type: 'fill', token: account.token }, f.sender)).ok, false);
  assert.equal(f.calls.fills.length, 0);
  assert.equal((await f.controller.handle({ type: 'fill', token: account.token, confirmOrigin: 'https://bank.example' }, f.sender)).ok, true);
  assert.equal(f.calls.fills.length, 1);
});
