import './vendor/nacl-fast.js';

const nacl = globalThis.nacl;
const HOST = 'com.markmcguill.strongbox';
const MAX_WIRE_BYTES = 1024 * 1024;
const MAX_RESULTS = 24;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function requireValue(condition) {
  if (!condition) throw new Error('Invalid native response');
}

function string(value, max, allowEmpty = true) {
  requireValue(typeof value === 'string' && value.length <= max && (allowEmpty || value.length > 0));
  return value;
}

function base64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function bytes(value, exactLength, minimum = 0) {
  requireValue(typeof value === 'string' && value.length <= MAX_WIRE_BYTES
    && value.length % 4 === 0 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value));
  const binary = atob(value);
  const decoded = Uint8Array.from(binary, character => character.charCodeAt(0));
  requireValue(base64(decoded) === value && decoded.length >= minimum
    && (exactLength === undefined || decoded.length === exactLength));
  return decoded;
}

function validateUrl(value) {
  requireValue(typeof value === 'string' && value.length > 0 && value.length <= 8192);
  const url = new URL(value);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  requireValue((url.protocol === 'https:' || (url.protocol === 'http:' && loopback))
    && !url.username && !url.password && (url.href === value || url.origin === value));
  return value;
}

function statusSchema(value) {
  requireValue(record(value) && Array.isArray(value.databases) && value.databases.length <= 256);
  const databases = value.databases.map(database => {
    requireValue(record(database) && typeof database.locked === 'boolean'
      && typeof database.autoFillEnabled === 'boolean');
    return {
      uuid: string(database.uuid, 128, false),
      nickName: string(database.nickName, 256),
      locked: database.locked,
      autoFillEnabled: database.autoFillEnabled,
    };
  });
  requireValue(value.serverSettings == null || record(value.serverSettings));
  const serverSettings = {};
  for (const key of ['supportsCreateNew', 'markdownNotes', 'colorizePasswords', 'colorBlindPalette']) {
    if (value.serverSettings?.[key] !== undefined) {
      requireValue(typeof value.serverSettings[key] === 'boolean');
      serverSettings[key] = value.serverSettings[key];
    }
  }
  return { databases, serverVersionInfo: string(value.serverVersionInfo, 128), serverSettings };
}

function credentialsSchema(value, search = false) {
  requireValue(record(value) && Array.isArray(value.results) && value.results.length <= MAX_RESULTS
    && (search || (Number.isSafeInteger(value.unlockedDatabaseCount) && value.unlockedDatabaseCount >= 0
    && value.unlockedDatabaseCount <= 256)));
  const results = value.results.map(credential => {
    requireValue(record(credential));
    return {
      uuid: string(credential.uuid, 128, false),
      databaseId: string(credential.databaseId, 128, false),
      title: string(credential.title, 8192),
      username: string(credential.username, 8192),
      password: string(credential.password, 65536),
      url: string(credential.url, 8192),
    };
  });
  return search ? { results } : { results, unlockedDatabaseCount: value.unlockedDatabaseCount };
}

// This session key check detects endpoint changes. The initial self-supplied
// server key does not authenticate Strongbox's identity or fix local IPC trust.
export class NativeClient {
  #send;
  #timeoutMs;
  #keyPair;
  #serverKey;
  #generation = 0;
  #busy = false;
  #transportPending = false;

  constructor(sendNativeMessage, { timeoutMs = 10000 } = {}) {
    if (typeof sendNativeMessage !== 'function' || !Number.isSafeInteger(timeoutMs)
      || timeoutMs < 1 || timeoutMs > 10000) throw new Error('Invalid native client configuration');
    this.#send = sendNativeMessage;
    this.#timeoutMs = timeoutMs;
  }

  clear() {
    this.#generation += 1;
    this.#keyPair?.secretKey.fill(0);
    this.#keyPair?.publicKey.fill(0);
    this.#serverKey?.fill(0);
    this.#keyPair = undefined;
    this.#serverKey = undefined;
  }

  async status() {
    return this.#request(0, null, statusSchema);
  }

  async credentialsForUrl(url) {
    validateUrl(url);
    if (!this.#keyPair || !this.#serverKey) throw new Error('Native status required');
    return this.#request(2, { url, skip: 0, take: MAX_RESULTS, subdomainMatching: true }, credentialsSchema);
  }

  async search(query, skip = 0) {
    requireValue(typeof query === 'string' && query.length <= 128
      && Number.isSafeInteger(skip) && skip >= 0 && skip <= 72);
    if (!this.#keyPair || !this.#serverKey) throw new Error('Native status required');
    return this.#request(1, { query, skip, take: MAX_RESULTS }, value => credentialsSchema(value, true));
  }

  async #request(messageType, payload, schema) {
    if (this.#busy || this.#transportPending) throw new Error('Native request already pending');
    this.#busy = true;
    let timer;
    let plaintext;
    let nonce;
    let ciphertext;
    let responseKey;
    try {
      if (!this.#keyPair) this.#keyPair = nacl.box.keyPair();
      const generation = this.#generation;
      const request = { messageType, clientPublicKey: base64(this.#keyPair.publicKey), nonce: '', message: '' };
      if (payload !== null) {
        nonce = nacl.randomBytes(nacl.box.nonceLength);
        plaintext = encoder.encode(JSON.stringify(payload));
        ciphertext = nacl.box(plaintext, nonce, this.#serverKey, this.#keyPair.secretKey);
        request.nonce = base64(nonce);
        request.message = base64(ciphertext);
        plaintext.fill(0);
      }
      this.#transportPending = true;
      const transport = Promise.resolve().then(() => this.#send(HOST, request));
      transport.then(() => { this.#transportPending = false; }, () => { this.#transportPending = false; });
      const response = await Promise.race([
        transport,
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Native request timed out')), this.#timeoutMs); }),
      ]);
      requireValue(generation === this.#generation && record(response)
        && Object.keys(response).length <= 8 && response.success === true);
      const wire = JSON.stringify(response);
      requireValue(wire.length <= MAX_WIRE_BYTES && encoder.encode(wire).length <= MAX_WIRE_BYTES);
      responseKey = bytes(response.serverPublicKey, nacl.box.publicKeyLength);
      nonce?.fill(0);
      nonce = bytes(response.nonce, nacl.box.nonceLength);
      ciphertext?.fill(0);
      ciphertext = bytes(response.message, undefined, nacl.box.overheadLength);
      requireValue(!this.#serverKey || nacl.verify(responseKey, this.#serverKey));
      plaintext = nacl.box.open(ciphertext, nonce, responseKey, this.#keyPair.secretKey);
      requireValue(plaintext !== null);
      const parsed = schema(JSON.parse(decoder.decode(plaintext)));
      if (!this.#serverKey) this.#serverKey = responseKey.slice();
      return parsed;
    } catch (error) {
      this.clear();
      throw new Error(error?.message === 'Native request timed out'
        ? 'Native request timed out' : 'Native request failed');
    } finally {
      clearTimeout(timer);
      plaintext?.fill(0);
      nonce?.fill(0);
      ciphertext?.fill(0);
      responseKey?.fill(0);
      this.#busy = false;
    }
  }
}
