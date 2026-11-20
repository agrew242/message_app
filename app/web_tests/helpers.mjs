// What the browser tests (run.mjs) and the screenshots (screenshots.mjs)
// share: a static server, a real relay, calls into the web glue, and finding
// things in the Flutter app through its accessibility tree.

import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
import http from 'node:http';
import { extname, join, normalize, sep } from 'node:path';

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

/** The web glue on its own, without the Flutter app. */
export const GLUE_PAGE = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<script src="messenger/vendor/jsQR.js"></script>
<script type="module">import './messenger/messenger_web.js';</script>
</body></html>`;

/** Serves `root`, plus a few generated pages (read on each request). */
export async function serve(root, extra = {}) {
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

export function chromePath() {
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

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// A real relay, and the web glue
// ---------------------------------------------------------------------------

/** Starts a relay with a fresh database in `dir`. Resolves once it answers. */
export async function startRelay(bin, dir, allowedOrigin) {
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
      await sleep(100);
    }
  }
  return { relay, url, invite };
}

/** Calls `window.messengerWeb[method]` and parses the envelope it returns. */
export const glue = (page, method, ...args) =>
  page.evaluate(async (m, a) => JSON.parse(await window.messengerWeb[m](...a)), method, args);

/** Like `glue`, but fails unless the call worked, and returns its value. */
export async function ok(page, method, ...args) {
  const env = await glue(page, method, ...args);
  assert.ok(env.ok, `${method}: ${env.kind}: ${env.message}`);
  return env.value;
}

/** Calls the encryption core through the glue's `invoke`. */
export const invoke = (page, method, ...args) => ok(page, 'invoke', method, JSON.stringify(args));

/** Collects live updates in `window.updates`. */
export async function listen(page) {
  await page.evaluate(() => {
    window.updates = [];
    window.messengerWeb.listen((text) => window.updates.push(JSON.parse(text)));
  });
}

/** Waits for a sync that brought an event of `type` (and `body`, if given). */
export function waitForEvent(page, type, body = null) {
  return page.waitForFunction(
    (t, b) =>
      window.updates.some((u) => u.type === 'events' && u.events.some((e) => e.type === t && (b === null || e.body === b))),
    { timeout: 15000 },
    type,
    body,
  );
}

// ---------------------------------------------------------------------------
// The Flutter app, through its accessibility tree (a build made with
// --dart-define=MESSENGER_SEMANTICS=true)
// ---------------------------------------------------------------------------

function axSearch(node, predicate) {
  if (!node) return null;
  if (predicate(node)) return node;
  for (const child of node.children ?? []) {
    const hit = axSearch(child, predicate);
    if (hit) return hit;
  }
  return null;
}

export async function axDump(page) {
  const lines = [];
  const walk = (n, depth) => {
    if (!n) return;
    if (n.role !== 'none' && n.role !== 'generic' || n.name) {
      lines.push(`${'  '.repeat(depth)}${n.role} ${JSON.stringify(n.name ?? '')}${n.value ? ` = ${JSON.stringify(n.value)}` : ''}`);
    }
    for (const c of n.children ?? []) walk(c, depth + 1);
  };
  walk(await page.accessibility.snapshot({ interestingOnly: false }), 0);
  return lines.slice(0, 200).join('\n');
}

/** The first accessibility node matching `predicate`, as an element. */
export async function axFind(page, predicate, what, timeout = 20000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const hit = axSearch(await page.accessibility.snapshot({ interestingOnly: false }), predicate);
    const handle = hit ? await hit.elementHandle() : null;
    if (handle) return { node: hit, handle };
    await sleep(250);
  }
  throw new Error(`${what} not found. The screen shows:\n${await axDump(page)}`);
}

export const name = (n) => (n.name ?? '').trim();
export const words = (n) => [n.name, n.value, n.description].filter(Boolean).join(' ');

/** A tap where the page has touch (a phone), else a click. */
export async function activate(page, handle) {
  if (page.viewport()?.hasTouch) await handle.tap();
  else await handle.click();
}

/** A button by its exact name, else one whose name starts with it. */
export async function button(page, label) {
  try {
    return await axFind(page, (n) => n.role === 'button' && name(n) === label, `button "${label}"`, 3000);
  } catch {
    return axFind(page, (n) => n.role === 'button' && name(n).startsWith(label), `button "${label}"`);
  }
}

/** Text on screen (not text still waiting in a text field). */
export const shows = (page, text) =>
  axFind(page, (n) => n.role !== 'textbox' && words(n).includes(text), `"${text}"`);

/** A text field by its label (or hint). */
export async function field(page, label, timeout = 20000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const boxes = [];
    const walk = (n) => {
      if (!n) return;
      if (n.role === 'textbox') boxes.push(n);
      for (const c of n.children ?? []) walk(c);
    };
    walk(await page.accessibility.snapshot({ interestingOnly: false }));
    const hit = boxes.find((n) => name(n).startsWith(label) || (n.description ?? '').trim().startsWith(label));
    const handle = hit ? await hit.elementHandle() : null;
    if (handle) return { node: hit, handle };
    await sleep(250);
  }
  throw new Error(`field "${label}" not found. The screen shows:\n${await axDump(page)}`);
}

export async function typeInto(page, label, text) {
  const { handle } = await field(page, label);
  await activate(page, handle);
  await sleep(150);
  // A multi-line field's accessibility node wraps the real text area.
  const editable = await handle.evaluateHandle((el) =>
    el.matches('input, textarea') ? el : el.querySelector('input, textarea'),
  );
  if (editable.asElement()) await editable.asElement().focus();
  // Insert the text the way a phone keyboard or autocorrect does. (Puppeteer's
  // synthetic key presses send Shift without a left/right location, which
  // Flutter's keyboard code doesn't expect from a real keyboard.)
  await page.keyboard.sendCharacter(text);
  await sleep(250);
  const focused = await page.evaluate(() => {
    const el = document.activeElement;
    return { tag: el?.tagName, value: el?.value ?? null };
  });
  if (!String(focused.value ?? '').includes(text)) {
    const now = await field(page, label);
    const dom = await handle.evaluate((el) => {
      const describe = (n) => n.outerHTML.replace(/>[^<]{40,}</g, '>…<').slice(0, 1500);
      return {
        node: describe(el),
        parent: el.parentElement ? describe(el.parentElement) : null,
        editors: [...document.querySelectorAll('input, textarea, [contenteditable]')].map(
          (e) => `${e.tagName} in <${e.parentElement?.tagName}> ${e.getAttribute('aria-label') ?? ''}`,
        ),
      };
    });
    throw new Error(
      `typing into "${label}" didn't stick: focus is on <${focused.tag}> holding ${JSON.stringify(focused.value)}; ` +
        `the field reads ${JSON.stringify(now.node.value ?? '')}\n` +
        `node: ${dom.node}\nparent: ${dom.parent}\neditors on the page: ${JSON.stringify(dom.editors)}`,
    );
  }
}

export async function press(page, label) {
  const { handle } = await button(page, label);
  await activate(page, handle);
}
