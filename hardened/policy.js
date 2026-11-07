import { matchesSavedUrl } from './domains.js';

const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_ITEMS = 64;
const MAX_FIELD = 8192;

export class ActionError extends Error {
  constructor(code) { super(code); this.code = code; }
}

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function text(value, maximum, allowEmpty = true) {
  if (typeof value !== 'string' || value.length > maximum || (!allowEmpty && !value.trim())) throw new Error('Invalid response');
  return value;
}

function bounded(value) {
  const encoded = JSON.stringify(value);
  if (typeof encoded !== 'string' || encoded.length > MAX_RESPONSE_BYTES || new TextEncoder().encode(encoded).length > MAX_RESPONSE_BYTES) throw new Error('Invalid response');
}

export function approvedUrl(value, { allowLoopback = false, allowOriginOnly = false } = {}) {
  text(value, 8192, false);
  let url;
  try { url = new URL(value); } catch { throw new ActionError('unsupported-page'); }
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (url.username || url.password || (url.protocol !== 'https:' && !(allowLoopback && url.protocol === 'http:' && loopback))) throw new ActionError('unsupported-page');
  // Reject inputs whose browser interpretation differs from the stored URL.
  if ((url.href !== value && !(allowOriginOnly && url.origin === value)) || url.origin === 'null') throw new ActionError('unsupported-page');
  return url;
}

export function validateContext(result, tabId, options = {}) {
  if (!Array.isArray(result) || result.length !== 1 || result[0]?.frameId !== 0) throw new Error('Invalid page');
  const entry = result[0];
  text(entry.documentId, 128, false);
  if (!/^[a-zA-Z0-9_-]+$/.test(entry.documentId) || !record(entry.result)) throw new Error('Invalid document');
  const url = approvedUrl(entry.result.url, options);
  if (entry.result.origin !== url.origin || entry.result.host !== url.host || !Number.isInteger(tabId) || tabId < 0) throw new Error('Invalid page');
  return { url: url.href, origin: url.origin, host: url.host, documentId: entry.documentId, tabId };
}

export function sameContext(left, right) {
  return !!left && !!right && ['url', 'origin', 'host', 'documentId', 'tabId'].every(key => left[key] === right[key]);
}

export function summarizeStatus(value) {
  bounded(value);
  if (!record(value) || !Array.isArray(value.databases) || value.databases.length > 128 || !record(value.serverSettings)) throw new Error('Invalid status');
  const version = text(value.serverVersionInfo, 128, false);
  let unlockedCount = 0;
  for (const database of value.databases) {
    if (!record(database) || typeof database.autoFillEnabled !== 'boolean' || typeof database.locked !== 'boolean') throw new Error('Invalid status');
    text(database.uuid, 256, false);
    text(database.nickName, 1024);
    if (database.autoFillEnabled && !database.locked) unlockedCount += 1;
  }
  return { version, unlockedCount };
}

export function selectCredentials(response, context, options = {}) {
  bounded(response);
  if (!record(response) || !Array.isArray(response.results) || response.results.length > MAX_ITEMS || !Number.isInteger(response.unlockedDatabaseCount) || response.unlockedDatabaseCount < 0 || response.unlockedDatabaseCount > 128) throw new Error('Invalid credentials');
  const items = [];
  for (const entry of response.results) {
    if (!record(entry)) throw new Error('Invalid credential');
    // Invalid or ambiguous stored URLs are excluded, never treated as matches.
    let url;
    try { url = approvedUrl(entry.url, { ...options, allowOriginOnly: true }); } catch { continue; }
    if (!matchesSavedUrl(url, approvedUrl(context.origin, { ...options, allowOriginOnly: true }))) continue;
    const databaseId = text(entry.databaseId, 256, false);
    const title = text(entry.title, 1024);
    const username = text(entry.username, MAX_FIELD);
    const password = text(entry.password, MAX_FIELD, false);
    items.push({ databaseId, title, username, password });
  }
  return items;
}

// These two functions are serialized by chrome.scripting. Keep them self-contained.
export function probeDocument() {
  if (window.top !== window) return null;
  return { url: location.href, origin: location.origin, host: location.host };
}

export function fillDocument(payload) {
  const fail = (reason = 'form-unavailable') => ({ filled: false, reason });
  if (!payload || typeof payload.username !== 'string' || typeof payload.password !== 'string' || payload.username.length > 8192 || !payload.password || payload.password.length > 8192) return fail();
  if (window.top !== window || location.href !== payload.url || location.origin !== payload.origin) return fail('page-changed');
  const tokens = input => input.autocomplete.toLowerCase().split(/\s+/);
  const visible = input => {
    if (!(input instanceof HTMLInputElement) || !input.isConnected || input.disabled || input.readOnly || input.type === 'hidden') return false;
    const rect = input.getBoundingClientRect();
    if (rect.width < 50 || rect.height < 10 || rect.top < 0 || rect.left < 0 || rect.bottom > innerHeight || rect.right > innerWidth) return false;
    const inputStyle = getComputedStyle(input);
    if (inputStyle.visibility !== 'visible' || inputStyle.pointerEvents === 'none') return false;
    for (let node = input; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.display === 'none' || Number.parseFloat(style.opacity) < 0.8) return false;
    }
    return document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2) === input;
  };
  function setField(field, value) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    if (!setter) return false;
    setter.call(field, value);
    field.dispatchEvent(new Event('input', { bubbles: true }));
    field.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  }
  const inputs = Array.from(document.querySelectorAll('input'));
  if (inputs.some(input => tokens(input).includes('new-password') && visible(input))) return fail();
  const passwords = inputs.filter(input => input.type === 'password' && !tokens(input).includes('new-password') && !tokens(input).includes('one-time-code') && visible(input));
  if (passwords.length === 0 && !inputs.some(input => input.type === 'password')) {
    const candidates = inputs.filter(input => ['text', 'email', 'tel'].includes(input.type)
      && tokens(input).some(token => token === 'username' || token === 'email') && visible(input));
    if (candidates.length !== 1 || !payload.username || !setField(candidates[0], payload.username)) return fail();
    return { filled: true, usernameOnly: true };
  }
  if (passwords.length !== 1) return fail();
  const password = passwords[0];
  const scope = password.form || document;
  if (Array.from(scope.querySelectorAll('input')).some(input => tokens(input).includes('new-password'))) return fail();
  const usernames = inputs.filter(input => {
    if (input === password || input.form !== password.form || !['text', 'email', 'tel'].includes(input.type) || !visible(input)) return false;
    if (!(input.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING)) return false;
    const hint = `${input.name} ${input.id}`.toLowerCase();
    return tokens(input).includes('username') || tokens(input).includes('email') || input.type === 'email' || /user|email|login|account/.test(hint);
  });
  if (usernames.length > 1) return fail();
  const username = usernames[0];
  const stillBound = () => location.href === payload.url && location.origin === payload.origin && password.type === 'password' && visible(password) && password.form === (scope === document ? null : scope);
  if (!stillBound()) return fail();
  // The password goes only to this one preselected field in the bound document.
  if (username && payload.username) {
    if (!visible(username)) return fail();
    if (!setField(username, payload.username)) return fail();
  }
  if (location.href !== payload.url || location.origin !== payload.origin) return fail('page-changed');
  if (!stillBound() || tokens(password).includes('new-password')) return fail();
  if (!setField(password, payload.password)) return fail();
  return { filled: true };
}
