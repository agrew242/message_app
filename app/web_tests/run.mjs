// Browser tests for the web app, in real Chrome (headless).
//
//   node run.mjs
//       Encrypted storage (IndexedDB, Web Crypto, the PIN) and photo
//       preparation (canvas).
//   RELAY_BIN=../../target/debug/messenger-relay node run.mjs
//       Also end to end: two people in two browser profiles, through the
//       WebAssembly build in web/pkg and a real relay on another origin.
//   FLUTTER_BUILD=../build/web node run.mjs
//       Also: the built Flutter app boots without errors.
//
// CHROME_PATH picks the browser (default: google-chrome).

import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, readdir, stat } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { extname, join, normalize, resolve, sep } from 'node:path';
import puppeteer from 'puppeteer-core';

const here = resolve(new URL('.', import.meta.url).pathname);
const webRoot = resolve(here, '../web');
const TYPES = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.mjs': 'text/javascript',
  '.json': 'application/json',
  '.wasm': 'application/wasm',
  '.png': 'image/png',
  '.ttf': 'font/ttf',
  '.otf': 'font/otf',
  '.css': 'text/css',
  '.frag': 'text/plain',
};

const GLUE_PAGE = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<script src="messenger/vendor/jsQR.js"></script>
<script type="module">import './messenger/messenger_web.js';</script>
</body></html>`;

/** Serves `root`, plus a few generated pages. */
async function serve(root, extra = {}) {
  const server = http.createServer(async (req, res) => {
    const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (extra[path] !== undefined) {
      res.writeHead(200, { 'content-type': TYPES[extname(path)] ?? 'text/html', 'cache-control': 'no-store' });
      res.end(extra[path]);
      return;
    }
    const file = normalize(join(root, path.endsWith('/') ? `${path}index.html` : path));
    if (!file.startsWith(root + sep) && file !== root) {
      res.writeHead(403).end();
      return;
    }
    try {
      if (!(await stat(file)).isFile()) throw new Error('not a file');
      res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' });
      res.end(await readFile(file));
    } catch {
      res.writeHead(404).end();
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

function chromePath() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  for (const name of ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser']) {
    try {
      return execFileSync('which', [name]).toString().trim();
    } catch {
      // try the next one
    }
  }
  throw new Error('no Chrome found; set CHROME_PATH');
}

let failures = 0;
async function test(name, fn) {
  const started = Date.now();
  try {
    await fn();
    console.log(`ok   ${name} (${Date.now() - started} ms)`);
  } catch (e) {
    failures++;
    console.log(`FAIL ${name}\n${e?.stack ?? e}`);
  }
}

/** A fresh browser profile on `url`, with page errors collected. */
async function openPage(browser, url) {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  page.errors = [];
  page.on('pageerror', (e) => page.errors.push(String(e)));
  page.on('console', (m) => {
    if (m.type() === 'error') console.log(`  [console] ${m.text()}`);
  });
  await page.goto(url);
  return { context, page };
}

// ---------------------------------------------------------------------------

async function storageTests(browser, base) {
  const { context, page } = await openPage(browser, `${base}/blank.html`);
  const log = await page.evaluate(async () => {
    const { Store } = await import('/messenger/store.js');
    const text = (bytes) => new TextDecoder().decode(bytes);
    const out = [];
    const attempt = async (fn) => {
      try {
        await fn();
        return 'ok';
      } catch (e) {
        return e.name;
      }
    };
    let s = await Store.open();
    out.push(await s.status());
    await s.reset();
    await s.save(new TextEncoder().encode('secret state, keys and all'));
    s = await Store.open();
    out.push(await s.status());
    out.push(text(await s.load()));
    out.push(text((await s.get('kv', 'state')).ct).includes('secret'));
    await s.putPhoto('p1', new Uint8Array([1, 2, 3]));
    out.push(Array.from(await s.getPhoto('p1')).join(','));
    out.push(await attempt(() => s.setPin('12')));
    await s.setPin('123456');
    s = await Store.open();
    out.push(await s.status());
    out.push(await attempt(() => s.unlock('000000')));
    out.push(text(await s.unlock('123456')));
    out.push(Array.from(await s.getPhoto('p1')).join(','));
    await s.setPin('654321');
    s = await Store.open();
    await s.status();
    out.push(await attempt(() => s.unlock('123456')));
    await s.unlock('654321');
    await s.setPin(null);
    s = await Store.open();
    out.push(await s.status());
    await s.wipe();
    s = await Store.open();
    out.push(await s.status());
    return out;
  });
  assert.deepEqual(log, [
    'new',
    'ready',
    'secret state, keys and all',
    false, // nothing readable at rest
    '1,2,3',
    'Invalid', // PIN too short
    'locked',
    'WrongPin',
    'secret state, keys and all',
    '1,2,3', // photos survive setting a PIN
    'WrongPin', // the old PIN after a change
    'ready', // PIN removed
    'new', // wiped
  ]);
  await context.close();
}

async function photoTests(browser, base) {
  const { context, page } = await openPage(browser, `${base}/blank.html`);
  const info = await page.evaluate(async () => {
    const { preparePhoto } = await import('/messenger/photos.js');
    const c = document.createElement('canvas');
    c.width = 3000;
    c.height = 2000;
    const ctx = c.getContext('2d');
    ctx.fillStyle = '#08f';
    ctx.fillRect(0, 0, 3000, 2000);
    const blob = await new Promise((r) => c.toBlob(r, 'image/png'));
    const p = await preparePhoto(new File([blob], 'big.png', { type: 'image/png' }));
    let bad = 'ok';
    try {
      await preparePhoto(new File([new Uint8Array([1, 2, 3])], 'x.png', { type: 'image/png' }));
    } catch (e) {
      bad = e.name;
    }
    return {
      size: [p.info.width, p.info.height],
      mime: p.info.mime,
      thumb: p.info.thumbnail.slice(0, 23),
      jpeg: p.bytes[0] === 0xff && p.bytes[1] === 0xd8,
      bad,
    };
  });
  assert.deepEqual(info, {
    size: [2048, 1365],
    mime: 'image/jpeg',
    thumb: 'data:image/jpeg;base64,',
    jpeg: true,
    bad: 'Invalid',
  });
  await context.close();
}

// ---------------------------------------------------------------------------
// End to end through the WebAssembly build and a real relay
// ---------------------------------------------------------------------------

async function startRelay(bin, dir, allowedOrigin) {
  const port = 19000 + Math.floor(Math.random() * 1000);
  const relay = spawn(bin, [], {
    env: {
      ...process.env,
      RELAY_ADDR: `127.0.0.1:${port}`,
      RELAY_DB: join(dir, 'relay.db'),
      RELAY_ALLOWED_ORIGINS: allowedOrigin,
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const invite = await new Promise((ok, fail) => {
    let out = '';
    relay.stdout.on('data', (d) => {
      out += d;
      const m = out.match(/invite code[^:]*: (\S+)/);
      if (m) ok(m[1]);
    });
    relay.on('exit', (code) => fail(new Error(`relay exited (${code})`)));
    setTimeout(() => fail(new Error('relay printed no invite')), 15000);
  });
  const url = `http://127.0.0.1:${port}`;
  for (let i = 0; ; i++) {
    try {
      if ((await fetch(`${url}/healthz`)).ok) break;
    } catch {
      if (i > 100) throw new Error('relay never came up');
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  return { relay, url, invite };
}

const glue = (page, method, ...args) =>
  page.evaluate(async (m, a) => JSON.parse(await window.messengerWeb[m](...a)), method, args);

async function ok(page, method, ...args) {
  const env = await glue(page, method, ...args);
  assert.ok(env.ok, `${method}: ${env.kind}: ${env.message}`);
  return env.value;
}

const invoke = (page, method, ...args) => ok(page, 'invoke', method, JSON.stringify(args));

async function listen(page) {
  await page.evaluate(() => {
    window.updates = [];
    window.messengerWeb.listen((text) => window.updates.push(JSON.parse(text)));
  });
}

/** Waits for a sync that brought an event of `type` (and `body`, if given). */
function waitForEvent(page, type, body = null) {
  return page.waitForFunction(
    (t, b) =>
      window.updates.some((u) => u.type === 'events' && u.events.some((e) => e.type === t && (b === null || e.body === b))),
    { timeout: 15000 },
    type,
    body,
  );
}

async function endToEnd(browser, relayBin) {
  const dir = await mkdtemp(join(tmpdir(), 'messenger-web-e2e-'));
  const extra = { '/glue.html': GLUE_PAGE };
  const { server, base } = await serve(webRoot, extra);
  const { relay, url, invite } = await startRelay(relayBin, dir, base);
  // config.json tells the app where the relay is.
  extra['/config.json'] = JSON.stringify({ relay: url });

  const secret = 'web canary 93f1c2 hello from Chrome';
  try {
    const alice = await openPage(browser, `${base}/glue.html`);
    const bob = await openPage(browser, `${base}/glue.html`);
    await alice.page.waitForFunction(() => window.messengerWeb);
    await bob.page.waitForFunction(() => window.messengerWeb);

    await test('e2e: sign up in the browser', async () => {
      const started = await ok(alice.page, 'start');
      assert.equal(started.state, 'new');
      assert.equal(started.relay, url);
      await listen(alice.page);
      await ok(alice.page, 'register', url, invite, 'alice');
      await invoke(alice.page, 'setDisplayName', 'Alice');
      const code = await invoke(alice.page, 'invite');
      assert.equal((await ok(bob.page, 'start')).state, 'new');
      await listen(bob.page);
      await ok(bob.page, 'register', url, code, 'bob');
    });

    let chat;
    await test('e2e: a chat, live delivery and receipts', async () => {
      chat = await invoke(alice.page, 'createChat', JSON.stringify(['bob']));
      await waitForEvent(bob.page, 'joined_chat');
      const sent = JSON.parse(await invoke(alice.page, 'sendText', chat, secret));
      await waitForEvent(bob.page, 'message', secret);
      await invoke(bob.page, 'markRead', chat);
      await waitForEvent(alice.page, 'receipt');
      await alice.page.waitForFunction(
        async (c, id) => {
          const env = JSON.parse(await window.messengerWeb.invoke('history', JSON.stringify([c])));
          return JSON.parse(env.value).some((m) => m.id === id && m.read_by.length === 1);
        },
        { timeout: 15000, polling: 250 },
        chat,
        sent.id,
      );
      const list = JSON.parse(await invoke(bob.page, 'chatList'));
      assert.equal(list[0].title, 'Alice');
    });

    await test('e2e: typing reaches the other side', async () => {
      await bob.page.evaluate((c) => window.messengerWeb.sendTyping(c), chat);
      await alice.page.waitForFunction(
        (c) => window.updates.some((u) => u.type === 'typing' && u.chat_id === c && u.who.startsWith('bob/')),
        { timeout: 10000 },
        chat,
      );
    });

    await test('e2e: a photo, picked, sent, cached and opened', async () => {
      const chooser = bob.page.waitForFileChooser();
      const sending = glue(bob.page, 'sendPhoto', chat);
      await (await chooser).accept([join(here, 'fixtures', 'photo.png')]);
      const env = await sending;
      assert.ok(env.ok, env.message);
      const message = env.value;
      assert.equal(message.attachment.width, 640);
      await waitForEvent(alice.page, 'message');
      const pic = await alice.page.waitForFunction(
        () => window.updates.flatMap((u) => u.events ?? []).find((e) => e.type === 'message' && e.attachment),
        { timeout: 15000 },
      );
      const attachment = (await pic.jsonValue()).attachment;
      const bytesOf = (page) =>
        page.evaluate(async (a) => {
          const env = JSON.parse(await window.messengerWeb.photoUrl(JSON.stringify(a)));
          if (!env.ok) throw new Error(env.message);
          return Array.from(new Uint8Array(await (await fetch(env.value)).arrayBuffer()));
        }, attachment);
      const theirs = await bytesOf(alice.page);
      const mine = await bytesOf(bob.page);
      assert.equal(theirs.length, mine.length);
      assert.deepEqual(theirs.slice(0, 2), [0xff, 0xd8]);
      assert.deepEqual(theirs, mine);
    });

    await test('e2e: nothing readable at rest, and only one tab at a time', async () => {
      const raw = await alice.page.evaluate(
        () =>
          new Promise((ok) => {
            const req = indexedDB.open('messenger');
            req.onsuccess = () => {
              const get = req.result.transaction('kv').objectStore('kv').get('state');
              get.onsuccess = () => ok(new TextDecoder().decode(get.result.ct));
            };
          }),
      );
      assert.ok(!raw.includes('hello from Chrome'));
      const second = await alice.context.newPage();
      await second.goto(`${base}/glue.html`);
      await second.waitForFunction(() => window.messengerWeb);
      const env = JSON.parse(await second.evaluate(() => window.messengerWeb.start()));
      assert.equal(env.value.state, 'busy');
      await second.close();
    });

    await test('e2e: a PIN locks the data until it is entered', async () => {
      await ok(alice.page, 'setPin', '246810');
      await alice.page.reload();
      await alice.page.waitForFunction(() => window.messengerWeb);
      assert.equal((await ok(alice.page, 'start')).state, 'locked');
      const wrong = await glue(alice.page, 'unlock', '135790');
      assert.equal(wrong.kind, 'WrongPin');
      await listen(alice.page);
      await ok(alice.page, 'unlock', '246810');
      const history = JSON.parse(await invoke(alice.page, 'history', chat));
      assert.ok(history.some((m) => m.body === secret));
      await invoke(bob.page, 'sendText', chat, 'after the reload');
      await waitForEvent(alice.page, 'message', 'after the reload');
    });

    await test('e2e: the relay never saw plaintext', async () => {
      for (const name of await readdir(dir)) {
        if (!name.startsWith('relay.db')) continue;
        const bytes = await readFile(join(dir, name));
        assert.ok(!bytes.includes(Buffer.from(secret)), `plaintext in ${name}`);
      }
    });

    await test('e2e: no uncaught errors in either browser', async () => {
      assert.deepEqual(alice.page.errors, []);
      assert.deepEqual(bob.page.errors, []);
    });
  } finally {
    relay.kill('SIGTERM');
    server.close();
  }
}

// ---------------------------------------------------------------------------
// The built Flutter app
// ---------------------------------------------------------------------------

async function flutterBoots(browser, buildDir) {
  const root = resolve(buildDir);
  const { server, base } = await serve(root, { '/config.json': JSON.stringify({ relay: 'https://relay.invalid' }) });
  try {
    const { context, page } = await openPage(browser, `${base}/`);
    await page.waitForFunction(() => !document.getElementById('loading'), { timeout: 30000 });
    await page.waitForSelector('flutter-view, flt-glass-pane', { timeout: 30000 });
    await page.waitForFunction(() => window.messengerWeb, { timeout: 30000 });
    // Give the app a moment to start the core and draw the sign-up screen.
    await new Promise((r) => setTimeout(r, 2000));
    const started = JSON.parse(await page.evaluate(() => window.messengerWeb.start()));
    assert.ok(started.ok, started.message);
    assert.equal(started.value.state, 'new');
    assert.deepEqual(page.errors, []);
    await context.close();
  } finally {
    server.close();
  }
}

// ---------------------------------------------------------------------------

const browser = await puppeteer.launch({
  executablePath: chromePath(),
  headless: true,
  args: ['--no-sandbox', '--disable-dev-shm-usage'],
});
try {
  const { server, base } = await serve(webRoot, { '/blank.html': '<!DOCTYPE html><meta charset="utf-8">' });
  await test('storage: encrypted at rest, PIN lock, photos, wipe', () => storageTests(browser, base));
  await test('photos: resized, re-encoded, thumbnailed', () => photoTests(browser, base));
  server.close();

  const relayBin = process.env.RELAY_BIN;
  if (relayBin && existsSync(join(webRoot, 'pkg', 'messenger_wasm_bg.wasm'))) {
    await endToEnd(browser, resolve(relayBin));
  } else {
    console.log('skip end to end (set RELAY_BIN and build web/pkg)');
  }

  if (process.env.FLUTTER_BUILD) {
    await test('flutter: the built app boots', () => flutterBoots(browser, process.env.FLUTTER_BUILD));
  }
} finally {
  await browser.close();
}

if (failures) {
  console.log(`${failures} failed`);
  process.exit(1);
}
console.log('all passed');
