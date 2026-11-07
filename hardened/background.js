import { matchesSavedUrl } from './domains.js';
import { NativeClient } from './native.js';
import { NATIVE_HOST, ALLOW_LOOPBACK } from './config.js';
import { ActionError, approvedUrl, fillDocument, probeDocument, sameContext, selectCredentials, summarizeStatus, validateContext } from './policy.js';

const SECRET_LIFETIME_MS = 45_000;
const FAILURE = Object.freeze({ ok: false, error: 'Unable to complete this action.' });
const ERRORS = Object.freeze({
  'unsupported-page': 'Open an HTTPS page, then reopen Strongbox Login.',
  'confirm-site': 'Confirm the destination before filling this account.',
  'page-changed': 'The page changed. Look up accounts again.',
  'expired': 'This account selection expired. Look up accounts again.',
  'form-unavailable': 'Open the email or password step, then choose the account again.',
  'database-locked': 'Database is locked or unavailable. Unlock it and look up accounts again.',
});
const failure = code => ERRORS[code] ? { ok: false, error: ERRORS[code] } : FAILURE;

export class BackgroundController {
  constructor(api, native, { now = Date.now, token = () => crypto.randomUUID(), allowLoopback = false, schedule = (...args) => setTimeout(...args), cancel = handle => clearTimeout(handle) } = {}) {
    this.api = api;
    this.native = native;
    this.now = now;
    this.token = token;
    this.options = { allowLoopback };
    this.schedule = schedule;
    this.cancel = cancel;
    this.entries = new Map();
    this.generation = 0;
    this.expiry = null;
    this.boundTabId = null;
  }

  clear() {
    this.generation += 1;
    if (this.expiry !== null) this.cancel(this.expiry);
    this.expiry = null;
    this.boundTabId = null;
    for (const entry of this.entries.values()) { entry.password = ''; entry.username = ''; }
    this.entries.clear();
    this.native.clear();
  }

  trusted(sender) {
    return !!sender && sender.id === this.api.runtime.id && sender.url === this.api.runtime.getURL('popup.html') && !sender.tab;
  }

  async context() {
    const tabs = await this.api.tabs.query({ active: true, currentWindow: true });
    if (tabs.length !== 1 || !Number.isInteger(tabs[0]?.id)) throw new Error('No page');
    const tabId = tabs[0].id;
    const results = await this.api.scripting.executeScript({ target: { tabId, frameIds: [0] }, func: probeDocument });
    return validateContext(results, tabId, this.options);
  }

  async handle(message, sender) {
    if (!this.trusted(sender)) return FAILURE;
    try {
      if (!message || typeof message !== 'object' || Array.isArray(message) || typeof message.type !== 'string') return FAILURE;
      if (message.type === 'context') return { ok: true, context: await this.context() };
      if (message.type === 'status') {
        const status = summarizeStatus(await this.native.status());
        return { ok: true, ...status };
      }
      if (message.type === 'lookup') return await this.lookup();
      if (message.type === 'search' && typeof message.query === 'string' && message.query.trim().length >= 2 && message.query.length <= 128) return await this.search(message.query.trim());
      if (message.type === 'fill' && typeof message.token === 'string' && message.token.length <= 128) return await this.fill(message.token, message.confirmOrigin);
      return FAILURE;
    } catch (error) {
      this.clear();
      return error instanceof ActionError ? failure(error.code) : FAILURE;
    }
  }

  async lookup() {
    this.clear();
    const generation = this.generation;
    const context = await this.context();
    if (generation !== this.generation) throw new ActionError('page-changed');
    this.boundTabId = context.tabId;
    const { unlockedCount } = summarizeStatus(await this.native.status());
    const beforeLookup = await this.context();
    if (generation !== this.generation || !sameContext(context, beforeLookup)) throw new ActionError('page-changed');
    const response = await this.native.credentialsForUrl(context.origin);
    const current = await this.context();
    if (generation !== this.generation || !sameContext(context, current)) throw new ActionError('page-changed');
    const items = selectCredentials(response, context, this.options);
    const publicItems = items.map(item => this.offer(item, context));
    this.expiry = this.schedule(() => this.clear(), SECRET_LIFETIME_MS);
    return { ok: true, items: publicItems, context, unlockedCount };
  }

  offer(item, context, search = false, savedOrigin = '') {
    const token = this.token();
    if (typeof token !== 'string' || token.length > 128 || !token || this.entries.has(token)) throw new Error('Invalid token');
    const requiresConfirmation = search && (!savedOrigin
      || !matchesSavedUrl(new URL(savedOrigin), new URL(context.origin)));
    this.entries.set(token, {
      databaseId: item.databaseId, username: item.username, password: item.password,
      context, expires: this.now() + SECRET_LIFETIME_MS, search, requiresConfirmation,
    });
    const result = { token, title: item.title, username: item.username };
    return search ? { ...result, savedOrigin, requiresConfirmation } : result;
  }

  async search(query) {
    const generation = this.generation;
    const context = await this.context();
    if (generation !== this.generation) throw new ActionError('page-changed');
    this.boundTabId = context.tabId;
    for (const [token, entry] of this.entries) {
      if (entry.search || entry.expires <= this.now()) this.entries.delete(token);
    }
    const status = await this.native.status();
    summarizeStatus(status);
    const unlocked = new Set(status.databases.filter(db => db.autoFillEnabled && !db.locked).map(db => db.uuid));
    const checkPage = async () => {
      const current = await this.context();
      if (generation !== this.generation || !sameContext(context, current)) throw new ActionError('page-changed');
    };
    await checkPage();
    const normalize = text => text.normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase();
    const needle = normalize(query);
    const score = title => {
      const name = normalize(title);
      const exact = name.indexOf(needle);
      if (exact >= 0) return exact;
      let position = -1;
      for (const letter of needle.replace(/\s/g, '')) {
        position = name.indexOf(letter, position + 1);
        if (position < 0) return Infinity;
      }
      return 10000 + position;
    };
    const matches = new Map();
    const collect = ({ results }) => {
      for (const item of results) {
        const rank = score(item.title);
        if (!Number.isFinite(rank) || !unlocked.has(item.databaseId) || !item.password || item.password.length > 8192) continue;
        matches.set(JSON.stringify([item.databaseId, item.uuid]), { item, rank });
      }
    };
    collect(await this.native.search(query));
    // Strongbox searches by words. Scan a bounded window for abbreviations when
    // the targeted query did not find an account name.
    let limited = false;
    if (!matches.size) {
      for (let skip = 0; skip <= 72; skip += 24) {
        await checkPage();
        const page = await this.native.search('', skip);
        collect(page);
        if (page.results.length < 24) break;
        limited = skip === 72;
      }
    }
    await checkPage();
    const items = [...matches.values()].sort((a, b) => a.rank - b.rank).slice(0, 24).map(({ item }) => {
      let savedOrigin = '';
      try { savedOrigin = approvedUrl(item.url, { ...this.options, allowOriginOnly: true }).origin; } catch {}
      return this.offer(item, context, true, savedOrigin);
    });
    if (this.expiry !== null) this.cancel(this.expiry);
    this.expiry = this.schedule(() => this.clear(), SECRET_LIFETIME_MS);
    return { ok: true, items, context, limited };
  }

  async fill(token, confirmOrigin) {
    const entry = this.entries.get(token);
    if (!entry || entry.expires <= this.now()) { this.clear(); return failure('expired'); }
    if (entry.requiresConfirmation && confirmOrigin !== entry.context.origin) return failure('confirm-site');
    // Consume all lookup tokens before the first await. A second click cannot replay them.
    const selected = { ...entry };
    const generation = this.generation + 1;
    this.clear();
    this.boundTabId = selected.context.tabId;
    try {
      const status = await this.native.status();
      summarizeStatus(status);
      if (generation !== this.generation) return failure('page-changed');
      if (!status.databases.some(database => database.uuid === selected.databaseId && database.autoFillEnabled && !database.locked)) return failure('database-locked');
      const current = await this.context();
      if (generation !== this.generation || !sameContext(selected.context, current)) return failure('page-changed');
      const results = await this.api.scripting.executeScript({
        target: { tabId: current.tabId, documentIds: [current.documentId] },
        func: fillDocument,
        args: [{ url: current.url, origin: current.origin, username: selected.username, password: selected.password }],
      });
      if (generation !== this.generation || !Array.isArray(results) || results.length !== 1 || results[0]?.documentId !== current.documentId || results[0]?.frameId !== 0) return failure('page-changed');
      if (results[0]?.result?.filled !== true) return failure(results[0]?.result?.reason === 'page-changed' ? 'page-changed' : 'form-unavailable');
      return results[0].result.usernameOnly ? { ok: true, usernameOnly: true } : { ok: true };
    } finally {
      selected.username = '';
      selected.password = '';
      selected.databaseId = '';
      if (generation === this.generation) { this.boundTabId = null; this.native.clear(); }
    }
  }

  onUpdated(tabId, changeInfo) {
    if (tabId === this.boundTabId && changeInfo && (changeInfo.status === 'loading' || typeof changeInfo.url === 'string')) this.clear();
  }

  onRemoved(tabId) { if (tabId === this.boundTabId) this.clear(); }
}

if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage && chrome.scripting) {
  const native = new NativeClient((_host, request) => chrome.runtime.sendNativeMessage(NATIVE_HOST, request));
  const controller = new BackgroundController(chrome, native, { allowLoopback: ALLOW_LOOPBACK === true });
  chrome.runtime.onMessage.addListener((message, sender, respond) => {
    controller.handle(message, sender).then(respond, () => respond(FAILURE));
    return true;
  });
  chrome.tabs.onUpdated.addListener((tabId, info) => controller.onUpdated(tabId, info));
  chrome.tabs.onRemoved.addListener(tabId => controller.onRemoved(tabId));
}
