// The web app's bridge to the encryption core (Rust, compiled to
// WebAssembly). Dart calls `window.messengerWeb`; everything it gets back is
// a JSON string, an "envelope": {ok: true, value} or {ok: false, kind,
// message}. Long-running parts of the web platform live here too: encrypted
// storage, the live connection, photos, the QR scanner and push.

import init, { Messenger } from '../pkg/messenger_wasm.js';
import { Live } from './live.js';
import { pickImageFile, preparePhoto } from './photos.js';
import { scanQrCode } from './qr.js';
import { namedError, Store } from './store.js';

/** Session methods Dart may call through `invoke(method, argsJson)`. */
const CALLABLE = new Set([
  'whoami',
  'chatList',
  'history',
  'members',
  'contacts',
  'nameOf',
  'safetyNumber',
  'invite',
  'createChat',
  'addMembers',
  'removeMembers',
  'removeDevices',
  'rotateKeys',
  'forgetChat',
  'sendText',
  'markRead',
  'setDisplayName',
  'setReadReceipts',
  'verifyCode',
  'markVerified',
  'resetVerification',
]);

let messenger = null;
let store = null;
let live = null;
let started = null;
const listeners = [];
const photoUrls = new Map();

function envelope(value) {
  return JSON.stringify({ ok: true, value: value ?? null });
}

function failure(e) {
  const kind = e?.name && e.name !== 'Error' ? e.name : 'Error';
  return JSON.stringify({ ok: false, kind, message: e?.message ?? String(e) });
}

async function guard(fn) {
  try {
    return envelope(await fn());
  } catch (e) {
    console.warn(e);
    return failure(e);
  }
}

function emit(update) {
  const text = JSON.stringify(update);
  for (const listener of listeners) {
    try {
      listener(text);
    } catch (e) {
      console.error(e);
    }
  }
}

function isIOS() {
  return /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
}

function isStandalone() {
  return window.matchMedia?.('(display-mode: standalone)').matches || navigator.standalone === true;
}

function pushSupported() {
  return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
}

function needMessenger() {
  if (!messenger) throw namedError('Locked', 'Not signed in yet');
  return messenger;
}

async function readConfig() {
  try {
    const res = await fetch('config.json', { cache: 'no-store' });
    if (res.ok) return await res.json();
  } catch {
    // No config: the person types the relay's address.
  }
  return {};
}

/** Only one tab may run the session: two would fight over its keys. */
function claimThisTab() {
  if (!navigator.locks) return Promise.resolve(true);
  return new Promise((resolve) => {
    navigator.locks.request('messenger-session', { ifAvailable: true }, (lock) => {
      resolve(lock !== null);
      // Hold it for as long as this page lives.
      return lock ? new Promise(() => {}) : undefined;
    });
  });
}

async function cachePhotos(events) {
  for (const e of events) {
    const a = e.type === 'message' ? e.attachment : null;
    if (!a) continue;
    try {
      if (await store.getPhoto(a.blob_id)) continue;
      const bytes = await messenger.fetchAttachment(JSON.stringify(a));
      await store.putPhoto(a.blob_id, bytes);
    } catch (err) {
      console.warn('photo download failed', err);
    }
  }
}

function base64UrlToBytes(text) {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(text.length / 4) * 4, '=');
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function refreshPush() {
  if (!pushSupported() || Notification.permission !== 'granted') return false;
  const reg = await navigator.serviceWorker.register('sw.js');
  await navigator.serviceWorker.ready;
  let sub = await reg.pushManager.getSubscription();
  if (!sub) {
    sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: base64UrlToBytes(await messenger.pushKey()),
    });
  }
  await messenger.setPush(JSON.stringify(sub));
  return true;
}

function begin(m) {
  messenger = m;
  live?.stop();
  live = new Live(messenger, emit, (events) => cachePhotos(events));
  live.start();
  // Push subscriptions can change; tell the relay the current one.
  refreshPush().catch((e) => console.warn('push refresh failed', e));
}

async function startOnce() {
  const config = await readConfig();
  const info = { state: 'new', relay: config.relay ?? '', ios: isIOS(), standalone: isStandalone(), push: pushSupported() };
  if (!window.indexedDB || !crypto?.subtle || typeof WebAssembly !== 'object') {
    return { ...info, state: 'unsupported' };
  }
  if (!(await claimThisTab())) return { ...info, state: 'busy' };
  await init({ module_or_path: new URL('../pkg/messenger_wasm_bg.wasm', import.meta.url) });
  store = await Store.open();
  const state = await store.status();
  if (state === 'ready') begin(Messenger.open(await store.load(), (bytes) => store.save(bytes)));
  return { ...info, state };
}

const api = {
  /** Loads everything. Resolves to {state: new|locked|ready|busy|unsupported, relay, ios, standalone, push}. */
  start() {
    started ??= startOnce();
    return guard(() => started);
  },

  register(relay, invite, username) {
    return guard(async () => {
      if (messenger) throw namedError('Invalid', 'Already signed in');
      await store.reset();
      begin(await Messenger.register(relay, invite, username, (bytes) => store.save(bytes)));
    });
  },

  unlock(pin) {
    return guard(async () => {
      const bytes = await store.unlock(pin);
      begin(Messenger.open(bytes, (b) => store.save(b)));
    });
  },

  invoke(method, argsJson) {
    return guard(async () => {
      if (!CALLABLE.has(method)) throw namedError('Invalid', `unknown method ${method}`);
      const m = needMessenger();
      return m[method](...JSON.parse(argsJson));
    });
  },

  /** `callback(json)` gets every live update. */
  listen(callback) {
    listeners.push(callback);
  },

  sendTyping(chatId) {
    live?.typing(chatId);
  },

  syncNow() {
    live?.syncSoon();
  },

  /** Opens the photo picker (call from a tap) and sends the photo. */
  sendPhoto(chatId) {
    const picked = pickImageFile();
    return guard(async () => {
      const file = await picked;
      if (!file) return null;
      const photo = await preparePhoto(file);
      const message = JSON.parse(await needMessenger().sendImage(chatId, photo.bytes, JSON.stringify(photo.info)));
      await store.putPhoto(message.attachment.blob_id, photo.bytes);
      return message;
    });
  },

  /** A blob: URL for a photo: from this device's cache, else downloaded. */
  photoUrl(attachmentJson) {
    return guard(async () => {
      const a = JSON.parse(attachmentJson);
      if (photoUrls.has(a.blob_id)) return photoUrls.get(a.blob_id);
      let bytes = await store.getPhoto(a.blob_id);
      if (!bytes) {
        bytes = await needMessenger().fetchAttachment(attachmentJson);
        await store.putPhoto(a.blob_id, bytes);
      }
      const url = URL.createObjectURL(new Blob([bytes], { type: a.mime }));
      photoUrls.set(a.blob_id, url);
      return url;
    });
  },

  /** Opens the camera to read a friend's code. Resolves to its text, or null. */
  scanQr() {
    return guard(() => scanQrCode());
  },

  /** {supported, permission: default|granted|denied, standalone, ios} */
  pushStatus() {
    return guard(async () => ({
      supported: pushSupported(),
      permission: pushSupported() ? Notification.permission : 'unsupported',
      standalone: isStandalone(),
      ios: isIOS(),
    }));
  },

  /** Asks for notification permission (call from a tap) and subscribes. */
  enablePush() {
    const asked = pushSupported() ? Notification.requestPermission() : null;
    return guard(async () => {
      if (!asked) {
        throw namedError(
          'Unsupported',
          isIOS() && !isStandalone()
            ? 'On iPhone, add this app to your Home Screen first, then turn notifications on from there.'
            : "This browser can't show notifications.",
        );
      }
      if ((await asked) !== 'granted') throw namedError('Denied', 'Notifications are turned off for this app.');
      needMessenger();
      return refreshPush();
    });
  },

  hasPin() {
    return guard(() => store.hasPin());
  },

  /** Sets or changes the PIN, or removes it (null). */
  setPin(pin) {
    return guard(() => store.setPin(pin ?? null));
  },

  /** Shares text with the system share sheet, or copies it. */
  share(text) {
    return guard(async () => {
      if (navigator.share) {
        try {
          await navigator.share({ text });
          return 'shared';
        } catch (e) {
          if (e?.name === 'AbortError') return 'cancelled';
        }
      }
      await navigator.clipboard.writeText(text);
      return 'copied';
    });
  },

  /** The number on the app icon (Home Screen apps). */
  setBadge(count) {
    try {
      if (count > 0) navigator.setAppBadge?.(count);
      else navigator.clearAppBadge?.();
    } catch {
      // Not supported here.
    }
  },

  /** Deletes this device's account data from this browser. */
  wipe() {
    return guard(async () => {
      live?.stop();
      if (messenger) await messenger.clearPush().catch(() => {});
      await store.wipe();
      messenger = null;
    });
  },
};

window.messengerWeb = api;
