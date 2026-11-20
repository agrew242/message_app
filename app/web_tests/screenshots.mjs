// Screenshots of the real app at iPhone size: a short, made-up conversation
// between three friends, as one of them sees it.
//
//   RELAY_BIN=../../target/debug/messenger-relay FLUTTER_UI_BUILD=../build/web-ui \
//     node screenshots.mjs [out-dir]
//
// Alex uses the real app (the accessibility-tree build, as in run.mjs) in a
// phone-sized Chrome that presents itself as an iPhone running the app from
// its Home Screen, so the app lays itself out as it does there. Jordan and Sam
// use the same encryption core through the web glue, each in their own
// browser profile. If the app can't be driven as an iPhone, it tries again in
// a phone-sized desktop browser.
//
// The PNGs go to out-dir (default: screenshots/). With PRINT_SCREENSHOTS=1,
// each is also printed to the log as base64, between "@@SHOT <name> <bytes>@@"
// and "@@END@@" lines.

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import puppeteer from 'puppeteer-core';
import {
  GLUE_PAGE,
  activate,
  axDump,
  axFind,
  chromePath,
  field,
  glue,
  invoke,
  listen,
  ok,
  press,
  serve,
  shows,
  sleep,
  startRelay,
  typeInto,
  waitForEvent,
  words,
} from './helpers.mjs';
import { paintLakePhoto } from './photo.mjs';

const here = resolve(new URL('.', import.meta.url).pathname);
const relayBin = process.env.RELAY_BIN;
const buildDir = process.env.FLUTTER_UI_BUILD;
if (!relayBin || !buildDir) {
  console.log('Set RELAY_BIN and FLUTTER_UI_BUILD (see the top of this file).');
  process.exit(2);
}
const outDir = resolve(process.argv[2] ?? join(here, 'screenshots'));
const printShots = process.env.PRINT_SCREENSHOTS === '1';

/** An iPhone 15 or 16: its screen in points, and Safari's user agent. */
const SCREEN = { width: 393, height: 852, deviceScaleFactor: 3 };
const IPHONE_SAFARI =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) ' +
  'Version/26.0 Mobile/15E148 Safari/604.1';

async function save(name, png) {
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, `${name}.png`), png);
  console.log(`  saved ${name}.png (${png.length} bytes)`);
  if (printShots) {
    const text = png.toString('base64');
    const lines = [`@@SHOT ${name} ${png.length}@@`];
    for (let i = 0; i < text.length; i += 8000) lines.push(text.slice(i, i + 8000));
    lines.push('@@END@@');
    console.log(lines.join('\n'));
  }
}

/** Alex's phone: a fresh profile at iPhone size, presenting as one if `iphone`. */
async function openPhone(browser, url, iphone) {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  page.on('pageerror', (e) => console.log(`  [pageerror] ${e?.stack ?? e}`));
  page.on('console', (m) => {
    if (m.type() === 'error') console.log(`  [console] ${m.text()}`);
  });
  if (iphone) {
    // Flutter goes by navigator.platform to adapt to iOS; the app's own code
    // by the user agent.
    page.emulation = await page.createCDPSession();
    await page.emulation.send('Emulation.setUserAgentOverride', { userAgent: IPHONE_SAFARI, platform: 'iPhone' });
    // Opened from the Home Screen, the way the app is meant to be used.
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(Navigator.prototype, 'standalone', { get: () => true, configurable: true });
    });
  }
  await page.setViewport({ ...SCREEN, isMobile: iphone, hasTouch: iphone });
  await page.goto(url);
  return { context, page };
}

/** A friend: the web glue on its own, in a fresh profile. */
async function openFriend(browser, base) {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  page.on('pageerror', (e) => console.log(`  [friend pageerror] ${e?.stack ?? e}`));
  await page.goto(`${base}/glue.html`);
  await page.waitForFunction(() => window.messengerWeb);
  return { context, page };
}

/** The id of the chat a friend was added to: the first, or the one given. */
async function joined(page, chatId = null) {
  const found = await page.waitForFunction(
    (id) =>
      window.updates
        .flatMap((u) => (u.type === 'events' ? u.events : []))
        .find((e) => e.type === 'joined_chat' && (id === null || e.chat_id === id))?.chat_id,
    { timeout: 20000 },
    chatId,
  );
  return found.jsonValue();
}

/** The innermost node whose text includes `text`, as an element. */
async function innermost(page, text, timeout = 20000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    let best = null;
    const walk = (n, depth) => {
      if (!n) return;
      if (words(n).includes(text) && (!best || depth > best.depth)) best = { n, depth };
      for (const c of n.children ?? []) walk(c, depth + 1);
    };
    walk(await page.accessibility.snapshot({ interestingOnly: false }), 0);
    const handle = best ? await best.n.elementHandle() : null;
    if (handle) return handle;
    await sleep(250);
  }
  throw new Error(`"${text}" not found. The screen shows:\n${await axDump(page)}`);
}

async function back(page) {
  await press(page, 'Back');
  await sleep(900); // the page transition
}

async function scenario(browser, mode) {
  const iphone = mode === 'iphone';
  console.log(`As ${iphone ? 'an iPhone' : 'a phone-sized desktop browser'}:`);
  const dir = await mkdtemp(join(tmpdir(), 'messenger-shots-'));
  const extra = { '/glue.html': GLUE_PAGE };
  const { server, base } = await serve(resolve(buildDir), extra);
  const { relay, url, invite } = await startRelay(resolve(relayBin), dir, base);
  extra['/config.json'] = JSON.stringify({ relay: url });
  const contexts = [];
  let a = null;
  const snap = async (shot) => {
    // A mouse left over a button would show its tooltip (touch shows none).
    if (!iphone) await a.mouse.move(2, SCREEN.height - 2);
    await sleep(800); // let animations settle
    await save(`${mode}-${shot}`, Buffer.from(await a.screenshot({ type: 'png' })));
  };
  try {
    const alex = await openPhone(browser, `${base}/`, iphone);
    contexts.push(alex.context);
    a = alex.page;
    await a.waitForFunction(() => window.messengerWeb, { timeout: 30000 });
    console.log(`  platform ${await a.evaluate(() => navigator.platform)}`);

    // Alex signs up.
    await shows(a, 'Welcome to Messenger');
    await typeInto(a, 'Your name', 'Alex Rivera');
    await typeInto(a, 'Username', 'alex');
    await typeInto(a, 'Invite code', invite);
    await snap('1-sign-up');
    await press(a, 'Create account');
    await shows(a, 'No chats yet');

    // Two friends join with invites from Alex.
    const friends = {};
    for (const [username, displayName] of [
      ['jordan', 'Jordan Lee'],
      ['sam', 'Sam Patel'],
    ]) {
      const code = await invoke(a, 'invite');
      const friend = await openFriend(browser, base);
      contexts.push(friend.context);
      await ok(friend.page, 'start');
      await listen(friend.page);
      await ok(friend.page, 'register', url, code, username);
      await invoke(friend.page, 'setDisplayName', displayName);
      friends[username] = friend.page;
    }
    const { jordan: j, sam: s } = friends;
    console.log('  everyone has signed up');

    // Each message shows on Alex's screen before the next is sent.
    const fromFriend = async (page, chat, text) => {
      await invoke(page, 'sendText', chat, text);
      await shows(a, text);
    };
    const fromAlex = async (text) => {
      await typeInto(a, 'Message', text);
      await press(a, 'Send');
      await shows(a, text);
    };

    // Alex starts a chat with Jordan.
    await press(a, 'New chat');
    await typeInto(a, 'Usernames', 'jordan');
    await press(a, 'Start chat');
    await field(a, 'Message');
    const chat = await joined(j);
    await fromFriend(j, chat, 'Hey! Are we still on for Friday?');
    await fromAlex('Yes! 7pm at mine');
    await waitForEvent(j, 'message', 'Yes! 7pm at mine');
    await fromFriend(j, chat, "Perfect, I'll bring dessert");

    // A photo from Jordan, which Alex's phone downloads and decrypts.
    const photo = join(dir, 'lake.jpg');
    await writeFile(photo, await paintLakePhoto(j));
    const downloaded = a.waitForResponse(
      (r) => r.request().method() === 'GET' && r.url().includes('/v1/blobs/') && r.ok(),
      { timeout: 30000 },
    );
    downloaded.catch(() => {}); // awaited below; don't let a failed send leave it unhandled
    const picker = j.waitForFileChooser();
    const sending = glue(j, 'sendPhoto', chat);
    await (await picker).accept([photo]);
    const sent = await sending;
    assert.ok(sent.ok, `sendPhoto: ${sent.kind}: ${sent.message}`);
    await downloaded;
    await fromFriend(j, chat, 'The lake last weekend');
    await fromAlex('Wow, gorgeous!');
    await fromAlex('See you Friday');
    await waitForEvent(j, 'message', 'See you Friday');
    await invoke(j, 'markRead', chat);
    await shows(a, 'Seen');
    await j.evaluate((c) => window.messengerWeb.sendTyping(c), chat);
    await shows(a, '•••');
    await snap('2-chat');

    // Alex compares safety numbers with Jordan and marks them verified.
    await press(a, 'Chat details');
    const { handle: jordanRow } = await shows(a, '@jordan');
    await activate(a, jordanRow);
    await press(a, 'We compared: the numbers match');
    await press(a, 'They match');
    await shows(a, 'You verified');
    await snap('3-verified');

    // Meanwhile Sam writes, and starts a group for Friday.
    const samChat = await invoke(s, 'createChat', JSON.stringify(['alex']));
    await invoke(s, 'sendText', samChat, "What's your address again?");
    const group = await invoke(s, 'createChat', JSON.stringify(['alex', 'jordan']));
    await joined(j, group);
    await invoke(s, 'sendText', group, 'Made us a group for Friday');
    await invoke(j, 'sendText', group, 'Nice! Dessert is covered');
    await invoke(s, 'sendText', group, "I'll bring drinks");

    // Back to the chat list.
    await back(a);
    await shows(a, 'Add people');
    await back(a);
    await field(a, 'Message');
    await back(a);
    await shows(a, "What's your address again?");
    const { handle: groupRow } = await shows(a, "I'll bring drinks");
    await snap('4-chats');

    // The group.
    await activate(a, groupRow);
    await field(a, 'Message');
    const plan = 'Doors open at 7. Bring a jacket, we might sit outside';
    await fromAlex(plan);
    for (const friend of [j, s]) {
      await waitForEvent(friend, 'message', plan);
      await invoke(friend, 'markRead', group);
    }
    await axFind(
      a,
      (n) => words(n).includes('Seen by') && words(n).includes('Jordan') && words(n).includes('Sam'),
      '"Seen by" both',
    );
    await snap('5-group');

    // Settings, from Alex's picture on the chat list.
    await back(a);
    await shows(a, "What's your address again?");
    await activate(a, await innermost(a, 'Settings'));
    await shows(a, 'Read receipts');
    await snap('6-settings');
  } catch (e) {
    if (a) await snap('stopped-here').catch(() => {});
    throw e;
  } finally {
    for (const c of contexts) await c.close().catch(() => {});
    relay.kill('SIGTERM');
    server.closeAllConnections?.();
    server.close();
  }
}

const browser = await puppeteer.launch({
  executablePath: chromePath(),
  headless: true,
  args: ['--no-sandbox', '--disable-dev-shm-usage'],
});
try {
  await scenario(browser, 'iphone');
} catch (e) {
  console.log(`That stopped:\n${e?.stack ?? e}\n`);
  try {
    await scenario(browser, 'desktop');
  } catch (e2) {
    console.log(`That stopped too:\n${e2?.stack ?? e2}`);
    process.exitCode = 1;
  }
} finally {
  await browser.close();
}
