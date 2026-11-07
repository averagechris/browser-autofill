import test from 'node:test';
import assert from 'node:assert/strict';
import { approvedUrl, fillDocument, selectCredentials } from '../hardened/policy.js';

function page(specs) {
  const saved = Object.fromEntries(['window', 'location', 'document', 'HTMLInputElement', 'Node', 'getComputedStyle', 'innerHeight', 'innerWidth'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  let fields = [];
  const form = { querySelectorAll: () => fields };
  class Input {
    constructor(spec, index) {
      Object.assign(this, { type: 'text', autocomplete: '', isConnected: true, disabled: false, readOnly: false, name: '', id: '', parentElement: null, index, form, writes: [], events: [], style: { display: 'block', visibility: 'visible', opacity: '1', pointerEvents: 'auto' } }, spec);
      this.current = '';
    }
    get value() { return this.current; }
    set value(value) { this.writes.push(value); this.current = value; }
    getBoundingClientRect() { return { left: 10, right: 110, top: this.index * 40 + 10, bottom: this.index * 40 + 30, width: 100, height: 20 }; }
    compareDocumentPosition(other) { return this.index < other.index ? 4 : 2; }
    dispatchEvent(event) { this.events.push(event.type); return true; }
  }
  fields = specs.map((spec, index) => new Input(spec, index));
  const win = {}; win.top = win;
  Object.assign(globalThis, {
    window: win, location: { href: 'https://bank.example/login', origin: 'https://bank.example' },
    HTMLInputElement: Input, Node: { DOCUMENT_POSITION_FOLLOWING: 4 }, innerHeight: 1000, innerWidth: 1000,
    getComputedStyle: input => input.style,
    document: {
      querySelectorAll: () => fields,
      elementFromPoint: (x, y) => fields.find(input => { const r = input.getBoundingClientRect(); return !input.occluded && x >= r.left && x <= r.right && y >= r.top && y <= r.bottom; }) || null,
    },
  });
  return {
    fields,
    restore() { for (const [key, descriptor] of Object.entries(saved)) { if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key]; } },
  };
}
const payload = { url: 'https://bank.example/login', origin: 'https://bank.example', username: 'fixture-user', password: 'SYNTHETIC SECRET' };

test('one associated visible username/password pair fills without submitting or returning values', () => {
  const f = page([{ name: 'username' }, { type: 'password', autocomplete: 'current-password' }]);
  try {
    assert.deepEqual(fillDocument(payload), { filled: true });
    assert.deepEqual(f.fields.map(input => input.value), ['fixture-user', 'SYNTHETIC SECRET']);
    assert.deepEqual(f.fields.flatMap(input => input.events), ['input', 'change', 'input', 'change']);
  } finally { f.restore(); }
});

test('ambiguous, new-password, hidden, occluded and unrelated-document targets fail before writing any secret', () => {
  for (const specs of [
    [{ type: 'password' }, { type: 'password' }],
    [{ type: 'password', autocomplete: 'new-password' }],
    [{ type: 'password' }, { type: 'hidden', autocomplete: 'new-password' }],
    [{ type: 'password', style: { display: 'none', visibility: 'visible', opacity: '1', pointerEvents: 'auto' } }],
    [{ type: 'password', style: { display: 'block', visibility: 'visible', opacity: '0', pointerEvents: 'auto' } }],
    [{ type: 'password', occluded: true }],
    [{ type: 'password', style: { display: 'block', visibility: 'visible', opacity: '1', pointerEvents: 'none' } }],
    [{ type: 'password', disabled: true }],
    [{ name: 'username' }, { name: 'email' }, { type: 'password' }],
  ]) {
    const f = page(specs);
    try {
      assert.deepEqual(fillDocument(payload), { filled: false, reason: 'form-unavailable' });
      assert(f.fields.every(input => input.writes.length === 0));
    } finally { f.restore(); }
  }
  for (const mutate of [() => { location.href = 'https://bank.example/replaced'; }, () => { location.origin = 'https://attacker.example'; }, () => { window.top = {}; }]) {
    const f = page([{ type: 'password' }]);
    try { mutate(); assert.deepEqual(fillDocument(payload), { filled: false, reason: 'page-changed' }); assert.equal(f.fields[0].writes.length, 0); } finally { f.restore(); }
  }
});

test('production URL policy and returned-record filtering require a single exact HTTPS origin', () => {
  assert.throws(() => approvedUrl('http://127.0.0.1:57839/'));
  assert.equal(approvedUrl('http://127.0.0.1:57839/', { allowLoopback: true }).origin, 'http://127.0.0.1:57839');
  for (const url of ['http://bank.example/', 'https://bank.example@attacker.example/', 'https://bank.example/\nhttps://attacker.example/', 'bank.example', 'https://user:pass@bank.example/']) {
    assert.throws(() => approvedUrl(url));
  }
  const item = url => ({ databaseId: 'fixture-db', url, title: 'fixture', username: 'user', password: 'secret', totp: 'MUST NOT ESCAPE', notes: 'MUST NOT ESCAPE' });
  const selected = selectCredentials({ results: [item('https://bank.example/account'), item('https://bank.example'), item('https://attacker.example/'), item('https://bank.example.attacker.example/'), item(''), item('https://user:pass@bank.example/')], unlockedDatabaseCount: 1 }, { origin: 'https://bank.example' });
  assert.deepEqual(selected, Array.from({ length: 2 }, () => ({ databaseId: 'fixture-db', title: 'fixture', username: 'user', password: 'secret' })));
});

test('an email-first step fills only the identified username field', () => {
  const f = page([{ type: 'email', autocomplete: 'username webauthn' }]);
  try {
    assert.deepEqual(fillDocument(payload), { filled: true, usernameOnly: true });
    assert.deepEqual(f.fields[0].writes, ['fixture-user']);
  } finally { f.restore(); }
});


test('clickable login inputs inside a pointer-transparent wrapper still fill', () => {
  const wrapper = { parentElement: null, style: { display: 'block', visibility: 'visible', opacity: '1', pointerEvents: 'none' } };
  const f = page([
    { name: 'login-name3', parentElement: wrapper },
    { type: 'password', name: 'login-password3', parentElement: wrapper },
  ]);
  try {
    assert.deepEqual(fillDocument(payload), { filled: true });
    assert.deepEqual(f.fields.map(input => input.value), ['fixture-user', 'SYNTHETIC SECRET']);
  } finally { f.restore(); }
});
