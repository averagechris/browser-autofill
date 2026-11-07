import test from 'node:test';
import assert from 'node:assert/strict';
import { registrableDomain, matchesSavedUrl } from '../hardened/domains.js';
import { selectCredentials } from '../hardened/policy.js';

const matches = (saved, destination) => matchesSavedUrl(new URL(saved), new URL(destination));
test('a saved HTTPS parent matches Google sign-in, while narrower entries stay narrow', () => {
  assert.equal(matches('https://google.com', 'https://accounts.google.com/signin'), true);
  assert.equal(matches('https://google.com/', 'https://accounts.google.com/'), true);
  assert.equal(matches('https://example.co.uk/', 'https://login.example.co.uk/'), true);
  assert.equal(matches('https://login.example.com/', 'https://child.login.example.com/'), true);
  assert.equal(matches('https://login.example.com/', 'https://example.com/'), false);
  assert.equal(matches('https://mail.google.com/', 'https://accounts.google.com/'), false);
});

test('domain boundaries reject deceptive names, shared suffixes, ports and insecure schemes', () => {
  for (const [saved, destination] of [
    ['https://google.com/', 'https://google.com.attacker.com/'],
    ['https://google.com/', 'https://notgoogle.com/'],
    ['https://com/', 'https://accounts.google.com/'],
    ['https://co.uk/', 'https://login.example.co.uk/'],
    ['https://github.io/', 'https://alice.github.io/'],
    ['https://alice.github.io/', 'https://bob.github.io/'],
    ['https://appspot.com/', 'https://tenant.appspot.com/'],
    ['https://google.com/', 'https://accounts.google.com:8443/'],
    ['http://google.com/', 'https://accounts.google.com/'],
    ['https://google.com/', 'http://accounts.google.com/'],
    ['https://google.com./', 'https://accounts.google.com./'],
    ['https://127.0.0.1/', 'https://127.0.0.1.nip.io/'],
  ]) assert.equal(matches(saved, destination), false, `${saved} -> ${destination}`);
  assert.equal(matches('https://alice.github.io/', 'https://login.alice.github.io/'), true);
  assert.equal(matches('https://google.com:8443/', 'https://accounts.google.com:8443/'), true);
});

test('public suffix resolution respects wildcard, exception, private and IDNA rules', () => {
  for (const [host, expected] of [
    ['com', null], ['co.uk', null], ['example.co.uk', 'example.co.uk'],
    ['b.ck', null], ['a.b.ck', 'a.b.ck'], ['www.ck', 'www.ck'], ['a.www.ck', 'www.ck'],
    ['city.kawasaki.jp', 'city.kawasaki.jp'], ['a.city.kawasaki.jp', 'city.kawasaki.jp'],
    ['foo.kawasaki.jp', null], ['github.io', null], ['alice.github.io', 'alice.github.io'],
    ['localhost', null], ['foo.local', null], ['foo.internal', null], ['foo.test', null], ['foo.unknown-suffix', null], ['127.0.0.1', null], ['[::1]', null], ['google.com.', null],
    ['accounts.google.com', 'google.com'], ['xn--85x722f.xn--55qx5d.cn', 'xn--85x722f.xn--55qx5d.cn'],
  ]) assert.equal(registrableDomain(host), expected, host);
});

test('Google URL lookup accepts parent records but excludes public suffixes and unrelated credentials', () => {
  const credential = url => ({ databaseId: 'synthetic-db', title: 'Synthetic', username: 'fake', password: 'fake-password', url });
  const result = selectCredentials({unlockedDatabaseCount:1, results:[
    credential('https://google.com'), credential('https://accounts.google.com/'),
    credential('https://com/'), credential('https://mail.google.com/'), credential('https://google.com.attacker.com/'),
  ]}, {origin:'https://accounts.google.com'});
  assert.equal(result.length, 2);
});
