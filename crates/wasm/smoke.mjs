// Smoke test for the WebAssembly build, run by CI:
//
//   node crates/wasm/smoke.mjs target/debug/messenger-relay
//
// Starts a real relay, then drives two devices through the same Messenger
// class the web app uses: sign-up, a chat, names, messages both ways, a
// restart from saved state, receipts, a photo, typing over the WebSocket,
// verification, and finally a scan of the relay's files for plaintext.
// Needs Node 22+ (global fetch, WebSocket and Web Crypto).

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import init, { Messenger } from './pkg/messenger_wasm.js';

const relayBin = process.argv[2];
assert.ok(relayBin, 'usage: node smoke.mjs <path to messenger-relay>');

const dir = await mkdtemp(join(tmpdir(), 'messenger-smoke-'));
const port = 18000 + Math.floor(Math.random() * 1000);
const url = `http://127.0.0.1:${port}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

await init({ module_or_path: await readFile(new URL('./pkg/messenger_wasm_bg.wasm', import.meta.url)) });

const relay = spawn(relayBin, [], {
  env: { ...process.env, RELAY_ADDR: `127.0.0.1:${port}`, RELAY_DB: join(dir, 'relay.db') },
  stdio: ['ignore', 'pipe', 'inherit'],
});
const relayExited = new Promise((resolve) => relay.on('exit', resolve));

function step(name) {
  console.log(`- ${name}`);
}

try {
  const invite = await new Promise((resolve, reject) => {
    let out = '';
    relay.stdout.on('data', (d) => {
      out += d;
      const m = out.match(/invite code[^:]*: (\S+)/);
      if (m) resolve(m[1]);
    });
    relay.on('exit', (code) => reject(new Error(`relay exited early (${code})`)));
    setTimeout(() => reject(new Error('the relay never printed an invite')), 15000);
  });
  for (let i = 0; ; i++) {
    try {
      if ((await fetch(`${url}/healthz`)).ok) break;
    } catch {
      if (i > 100) throw new Error('relay never came up');
      await sleep(100);
    }
  }

  // Each device's "disk": whatever it last asked to save.
  const disks = {};
  const saver = (name) => async (bytes) => {
    disks[name] = new Uint8Array(bytes);
  };

  step('sign up and pick names');
  const alice = await Messenger.register(url, invite, 'alice', saver('alice'));
  await alice.setDisplayName('Alice');
  const bob = await Messenger.register(url, await alice.invite(), 'bob', saver('bob'));
  assert.ok(disks.alice && disks.bob, 'nothing was saved');

  step('start a chat');
  const chat = await alice.createChat(JSON.stringify(['bob']));
  let events = JSON.parse(await bob.sync());
  assert.ok(events.some((e) => e.type === 'joined_chat' && e.chat_id === chat), JSON.stringify(events));
  assert.equal(await bob.nameOf('alice'), 'Alice');
  const list = JSON.parse(await bob.chatList());
  assert.equal(list[0].title, 'Alice');

  step('send a message');
  const secret = 'smoke canary 4c1d77 hello from WebAssembly';
  const sent = JSON.parse(await alice.sendText(chat, secret));
  events = JSON.parse(await bob.sync());
  assert.deepEqual(
    events.filter((e) => e.type === 'message').map((e) => e.body),
    [secret],
  );

  step('restart from saved state and reply');
  const bob2 = Messenger.open(disks.bob, saver('bob'));
  await bob2.sendText(chat, 'reply after restart');
  events = JSON.parse(await alice.sync());
  assert.ok(events.some((e) => e.type === 'message' && e.body === 'reply after restart'));

  step('delivered and read receipts');
  await bob2.markRead(chat);
  await alice.sync();
  const mine = JSON.parse(await alice.history(chat)).find((m) => m.id === sent.id);
  assert.equal(mine.delivered_to.length, 1);
  assert.equal(mine.read_by.length, 1);

  step('send a photo');
  const photo = Uint8Array.from({ length: 50_000 }, (_, i) => i % 251);
  await alice.sendImage(chat, photo, JSON.stringify({ mime: 'image/png', width: 10, height: 10, caption: 'pic' }));
  events = JSON.parse(await bob2.sync());
  const pic = events.find((e) => e.type === 'message' && e.attachment);
  assert.ok(pic, JSON.stringify(events));
  assert.equal(pic.body, 'pic');
  const got = await bob2.fetchAttachment(JSON.stringify(pic.attachment));
  assert.deepEqual(Buffer.from(got), Buffer.from(photo));

  step('typing over the live WebSocket');
  const open = async (m) => {
    const ws = new WebSocket(await m.streamUrl());
    const updates = [];
    ws.onmessage = async (msg) => {
      updates.push(JSON.parse(await m.readStreamFrame(String(msg.data))));
    };
    await new Promise((resolve, reject) => {
      ws.onopen = resolve;
      ws.onerror = reject;
    });
    ws.send(await m.streamHello());
    // The next update of a given type, skipping others (such as a "mail"
    // hint for a receipt that was already waiting).
    const waitFor = async (type) => {
      for (const deadline = Date.now() + 5000; Date.now() < deadline; await sleep(20)) {
        const i = updates.findIndex((u) => u.type === type);
        if (i >= 0) return updates.splice(i, 1)[0];
      }
      throw new Error(`no ${type} update; got ${JSON.stringify(updates)}`);
    };
    return { ws, waitFor };
  };
  const aliceLive = await open(alice);
  await aliceLive.waitFor('ready');
  const bobLive = await open(bob2);
  await bobLive.waitFor('ready');
  bobLive.ws.send(await bob2.typingFrame(chat));
  const typing = await aliceLive.waitFor('typing');
  assert.equal(typing.chat_id, chat);
  assert.ok(typing.who.startsWith('bob/'));
  await bob2.sendText(chat, 'live');
  await aliceLive.waitFor('mail');
  aliceLive.ws.close();
  bobLive.ws.close();

  step('verify each other');
  const bobMe = JSON.parse(await bob2.whoami());
  assert.equal(await alice.verifyCode(bobMe.verification_code), 'verified');
  assert.equal(await alice.safetyNumber('bob'), await bob2.safetyNumber('alice'));
  const contacts = JSON.parse(await alice.contacts());
  assert.ok(contacts.find((c) => c.username === 'bob').verified);

  step('errors say what kind they are');
  await assert.rejects(alice.createChat(JSON.stringify(['nobody'])), (e) => e.name === 'Invalid');
  await assert.rejects(alice.sendText('00'.repeat(16), 'x'), (e) => e.name === 'NotFound');

  step('no plaintext on the relay');
  await alice.sync();
  await bob2.sync();
  relay.kill('SIGTERM');
  await relayExited;
  for (const name of await readdir(dir)) {
    if (!name.startsWith('relay.db')) continue;
    const bytes = await readFile(join(dir, name));
    assert.ok(!bytes.includes(Buffer.from(secret)), `found plaintext in ${name}`);
  }
  console.log('Smoke test passed.');
} finally {
  relay.kill('SIGTERM');
}
