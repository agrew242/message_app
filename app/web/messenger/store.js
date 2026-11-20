// Encrypted storage for the web app, in IndexedDB.
//
// Everything (the session's state and cached photos) is encrypted with
// AES-256-GCM under one random data key. Without an app PIN, the data key
// sits next to the data: that only protects against casual inspection of the
// browser's files. With a PIN, the data key is stored only wrapped by a key
// derived from the PIN (PBKDF2-SHA-256, 600,000 rounds), so the files are
// useless without it. Changing the PIN re-wraps the data key; nothing else
// is re-encrypted.

const DB_NAME = 'messenger';
const DB_VERSION = 1;
const STATE_AAD = new TextEncoder().encode('messenger-web-state-v1');
const PHOTO_AAD = new TextEncoder().encode('messenger-web-photo-v1');
const KEY_AAD = new TextEncoder().encode('messenger-web-data-key-v1');
const PIN_ROUNDS = 600_000;

export function namedError(name, message) {
  const e = new Error(message);
  e.name = name;
  return e;
}

function promised(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function finished(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? namedError('Storage', 'storage write was aborted'));
  });
}

async function importDataKey(raw) {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function pinKey(pin, salt, rounds) {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: rounds },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function seal(key, bytes, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, bytes));
  return { iv, ct };
}

async function open(key, sealed, aad) {
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: sealed.iv, additionalData: aad }, key, sealed.ct),
  );
}

export class Store {
  static async open() {
    const db = await new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        req.result.createObjectStore('kv');
        req.result.createObjectStore('photos');
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(namedError('Storage', 'close other tabs of this app and try again'));
    });
    return new Store(db);
  }

  constructor(db) {
    this.db = db;
    this.key = null; // the data key, for use
    this.raw = null; // its bytes, kept only to re-wrap when the PIN changes
    // Writes happen one at a time, in order.
    this.queue = Promise.resolve();
  }

  serial(fn) {
    const run = this.queue.then(fn);
    this.queue = run.catch(() => {});
    return run;
  }

  async get(store, k) {
    return promised(this.db.transaction(store, 'readonly').objectStore(store).get(k));
  }

  async write(store, puts, deletes = []) {
    const tx = this.db.transaction(store, 'readwrite', { durability: 'strict' });
    const s = tx.objectStore(store);
    for (const [k, v] of puts) s.put(v, k);
    for (const k of deletes) s.delete(k);
    await finished(tx);
  }

  /** 'new' (nothing saved), 'locked' (needs the PIN) or 'ready'. */
  async status() {
    if (!(await this.get('kv', 'state'))) return 'new';
    if (await this.get('kv', 'dk_pin')) return 'locked';
    const raw = await this.get('kv', 'dk');
    if (!raw) return 'new';
    this.raw = raw;
    this.key = await importDataKey(raw);
    return 'ready';
  }

  get unlocked() {
    return this.key !== null;
  }

  /** Forgets everything and starts over with a new data key. */
  async reset() {
    return this.serial(async () => {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      const tx = this.db.transaction(['kv', 'photos'], 'readwrite', { durability: 'strict' });
      tx.objectStore('kv').clear();
      tx.objectStore('photos').clear();
      tx.objectStore('kv').put(raw, 'dk');
      await finished(tx);
      this.raw = raw;
      this.key = await importDataKey(raw);
    });
  }

  async save(bytes) {
    return this.serial(async () => {
      if (!this.key) throw namedError('Storage', 'storage is locked');
      await this.write('kv', [['state', await seal(this.key, bytes, STATE_AAD)]]);
    });
  }

  async load() {
    const sealed = await this.get('kv', 'state');
    if (!sealed || !this.key) throw namedError('Storage', 'nothing saved yet');
    return open(this.key, sealed, STATE_AAD);
  }

  async hasPin() {
    return !!(await this.get('kv', 'dk_pin'));
  }

  /** Unwraps the data key with the PIN; a wrong PIN throws `WrongPin`. */
  async unlock(pin) {
    const wrapped = await this.get('kv', 'dk_pin');
    if (!wrapped) throw namedError('Storage', 'no PIN is set');
    const key = await pinKey(pin, wrapped.salt, wrapped.rounds);
    let raw;
    try {
      raw = await open(key, wrapped, KEY_AAD);
    } catch {
      throw namedError('WrongPin', "That PIN isn't right");
    }
    this.raw = raw;
    this.key = await importDataKey(raw);
    return this.load();
  }

  /** Sets, changes (pin) or removes (null) the PIN. Must be unlocked. */
  async setPin(pin) {
    return this.serial(async () => {
      if (!this.raw) throw namedError('Storage', 'storage is locked');
      if (pin === null) {
        await this.write('kv', [['dk', this.raw]], ['dk_pin']);
        return;
      }
      if (!/^\d{6,}$/.test(pin)) throw namedError('Invalid', 'Use at least 6 digits');
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const sealed = await seal(await pinKey(pin, salt, PIN_ROUNDS), this.raw, KEY_AAD);
      await this.write('kv', [['dk_pin', { ...sealed, salt, rounds: PIN_ROUNDS }]], ['dk']);
    });
  }

  async putPhoto(blobId, bytes) {
    return this.serial(async () => {
      if (!this.key) return;
      await this.write('photos', [[blobId, await seal(this.key, bytes, PHOTO_AAD)]]);
    });
  }

  async getPhoto(blobId) {
    const sealed = await this.get('photos', blobId);
    if (!sealed || !this.key) return null;
    try {
      return await open(this.key, sealed, PHOTO_AAD);
    } catch {
      return null;
    }
  }

  /** Deletes everything on this device. */
  async wipe() {
    return this.serial(async () => {
      const tx = this.db.transaction(['kv', 'photos'], 'readwrite', { durability: 'strict' });
      tx.objectStore('kv').clear();
      tx.objectStore('photos').clear();
      await finished(tx);
      this.key = null;
      this.raw = null;
    });
  }
}
