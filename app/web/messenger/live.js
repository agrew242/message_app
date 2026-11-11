// The live connection: a WebSocket to the relay that says "you have mail"
// (never what the mail is) and carries encrypted typing signals. Whenever it
// says so, or the app comes back to the foreground, we sync.

const MAX_BACKOFF_MS = 30_000;
const TYPING_EVERY_MS = 3_000;
const FALLBACK_SYNC_MS = 60_000;

export class Live {
  /**
   * @param messenger the wasm Messenger
   * @param emit called with plain objects for the app:
   *   {type: 'connection', online}, {type: 'typing', chat_id, who},
   *   {type: 'events', events}, {type: 'sync_error', kind, message}
   * @param afterSync called with each batch of events (to cache photos)
   */
  constructor(messenger, emit, afterSync = () => {}) {
    this.m = messenger;
    this.emit = emit;
    this.afterSync = afterSync;
    this.ws = null;
    this.online = false;
    this.backoff = 1000;
    this.stopped = false;
    this.syncing = false;
    this.again = false;
    this.lastTyping = new Map();
    this.onVisible = () => {
      if (document.visibilityState !== 'visible') return;
      if (!this.ws || this.ws.readyState > WebSocket.OPEN) this.connect();
      this.syncSoon();
    };
  }

  start() {
    document.addEventListener('visibilitychange', this.onVisible);
    window.addEventListener('online', this.onVisible);
    // In case the socket is blocked somewhere, still catch up now and then.
    this.timer = setInterval(() => {
      if (document.visibilityState === 'visible') this.syncSoon();
    }, FALLBACK_SYNC_MS);
    this.connect();
    this.syncSoon();
  }

  stop() {
    this.stopped = true;
    clearInterval(this.timer);
    clearTimeout(this.retry);
    document.removeEventListener('visibilitychange', this.onVisible);
    window.removeEventListener('online', this.onVisible);
    this.ws?.close();
  }

  setOnline(online) {
    if (this.online === online) return;
    this.online = online;
    this.emit({ type: 'connection', online });
  }

  async connect() {
    if (this.stopped) return;
    clearTimeout(this.retry);
    let ws;
    try {
      ws = new WebSocket(await this.m.streamUrl());
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.ws = ws;
    ws.onopen = async () => {
      try {
        ws.send(await this.m.streamHello());
      } catch {
        ws.close();
      }
    };
    ws.onmessage = async (msg) => {
      let update;
      try {
        update = JSON.parse(await this.m.readStreamFrame(String(msg.data)));
      } catch {
        return;
      }
      switch (update.type) {
        case 'ready':
          this.backoff = 1000;
          this.setOnline(true);
          this.syncSoon();
          break;
        case 'mail':
          this.syncSoon();
          break;
        case 'typing':
          this.emit(update);
          break;
        case 'error':
          console.warn('relay:', update.error);
          break;
      }
    };
    ws.onclose = () => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.setOnline(false);
      this.scheduleReconnect();
    };
    ws.onerror = () => {}; // onclose follows
  }

  scheduleReconnect() {
    if (this.stopped) return;
    clearTimeout(this.retry);
    this.retry = setTimeout(() => this.connect(), this.backoff);
    this.backoff = Math.min(this.backoff * 2, MAX_BACKOFF_MS);
  }

  /** Syncs now, or right after the sync already running. */
  async syncSoon() {
    if (this.syncing) {
      this.again = true;
      return;
    }
    this.syncing = true;
    try {
      do {
        this.again = false;
        const events = JSON.parse(await this.m.sync());
        if (events.length) {
          this.emit({ type: 'events', events });
          this.afterSync(events);
        }
      } while (this.again && !this.stopped);
    } catch (e) {
      if (e?.name === 'Offline') this.setOnline(false);
      this.emit({ type: 'sync_error', kind: e?.name ?? 'Error', message: e?.message ?? String(e) });
    } finally {
      this.syncing = false;
    }
  }

  /** Tells the chat we're typing, at most every few seconds. */
  async typing(chatId) {
    const now = Date.now();
    if (now - (this.lastTyping.get(chatId) ?? 0) < TYPING_EVERY_MS) return;
    this.lastTyping.set(chatId, now);
    if (this.ws?.readyState !== WebSocket.OPEN) return;
    try {
      this.ws.send(await this.m.typingFrame(chatId));
    } catch {
      // Not worth bothering anyone about.
    }
  }
}
