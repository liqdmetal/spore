// Tests the browser-side logic of cmd/spore/web/chat.html under a minimal DOM
// stub. Two behaviours here are invisible until they break in production:
//
//   1. the compost.* -> spore.* storage migration (a bad one silently wipes
//      every existing user's nickname, rooms, and friends), and
//   2. the onboarding panel actually yielding to the message view on every
//      path into a room.
//
// Run: node chat-ui.test.js cmd/spore/web/chat.html
const fs = require("fs");
const path = process.argv[2] || "cmd/spore/web/chat.html";

const html = fs.readFileSync(path, "utf8");
const m = html.match(/<script>([\s\S]*?)<\/script>/);
if (!m) { console.error("no <script> block found"); process.exit(1); }

// ---- minimal DOM stub ----
function makeEl(id) {
  const el = {
    id, style: {}, textContent: "", value: "", className: "",
    innerHTML: "", children: [], dataset: {},
    tagName: "DIV",
    appendChild(c) { this.children.push(c); return c; },
    prepend(c) { this.children.unshift(c); return c; },
    removeChild(c) { this.children = this.children.filter(x => x !== c); return c; },
    insertAdjacentHTML() {},
    querySelector() { return makeEl("q"); },
    querySelectorAll() { return []; },
    addEventListener() {},
    focus() {},
    setAttribute() {},
    getAttribute() { return null; },
  };
  return el;
}
const els = new Map();
global.document = {
  getElementById(id) { if (!els.has(id)) els.set(id, makeEl(id)); return els.get(id); },
  createElement() { return makeEl("new"); },
  addEventListener() {},
  activeElement: { tagName: "BODY" },
};
const store = new Map();
global.localStorage = {
  getItem: k => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: k => store.delete(k),
};
global.window = { location: { origin: "http://127.0.0.1:19192" }, addEventListener() {} };
global.navigator = { sendBeacon() {} };
global.fetch = () => Promise.reject(new Error("offline in test"));
global.prompt = () => null;
global.alert = () => {};
global.crypto = { getRandomValues: a => { for (let i = 0; i < a.length; i++) a[i] = i & 0xff; return a; },
  subtle: { importKey: async () => ({}), encrypt: async () => new Uint8Array(4), decrypt: async () => new Uint8Array(4) } };

// capture exported-for-test handles by appending a probe to the script
const probe = `
;globalThis.__t = { lsGet, lsSet, showWelcome, hideWelcome, state, join, whisperSend, whisperRecv };
`;
const runner = new Function("globalThis", m[1] + probe);
let failed = 0;
const ok = (cond, msg) => { if (!cond) { console.error("  FAIL:", msg); failed++; } else console.log("  ok:", msg); };

try {
  runner(globalThis);
} catch (e) {
  console.error("script threw during load:", e.message);
  process.exit(1);
}
const t = globalThis.__t;

console.log("storage migration");
// A pre-rename install: only compost.* keys exist.
store.clear();
store.set("compost.nick", "olduser");
store.set("compost.rooms", JSON.stringify({ "#legacy": "" }));
store.set("compost.friends", JSON.stringify({ "dero1qold": "Old Friend" }));
ok(t.lsGet("nick") === "olduser", "reads the legacy nickname (data survives the rename)");
ok(t.lsGet("rooms") !== null, "reads the legacy room list");
ok(t.lsGet("friends") !== null, "reads the legacy friends list");
ok(t.lsGet("missing", "dflt") === "dflt", "returns the default when neither key exists");

// Writes must go to the NEW key only.
t.lsSet("nick", "newuser");
ok(store.get("spore.nick") === "newuser", "writes the new spore.* key");
ok(store.get("compost.nick") === "olduser", "leaves the legacy key untouched (no destructive rewrite)");
ok(t.lsGet("nick") === "newuser", "new key wins over legacy once written");

console.log("onboarding");
ok(els.get("welcome").style.display === undefined || typeof els.get("welcome").style.display === "string",
   "welcome element is addressable");
t.showWelcome();
ok(els.get("welcome").style.display === "block", "showWelcome reveals the panel");
ok(els.get("messages").style.display === "none", "showWelcome hides the message list");
ok(els.get("compose").style.display === "none", "showWelcome hides the composer");
t.hideWelcome();
ok(els.get("welcome").style.display === "none", "hideWelcome hides the panel");
ok(els.get("messages").style.display === "flex", "hideWelcome restores the message list");
ok(els.get("compose").style.display === "flex", "hideWelcome restores the composer");

// The important one: entering a room by ANY path must dismiss onboarding.
t.showWelcome();
t.join("#somewhere").then(async () => {
  ok(els.get("welcome").style.display === "none",
     "join() dismisses the onboarding panel (clicking a room works, not just the buttons)");

  console.log("forward-compostable messaging (E2 endpoints)");
  const calls = [];
  global.fetch = async (url, opts) => {
    calls.push({ url: String(url), opts });
    return { ok: true, text: async () => "{}" };
  };
  document.getElementById("wTo").value = "dero1qyfriend";
  document.getElementById("wMsg").value = "hello";
  await t.whisperSend();
  ok(calls.some(c => c.url.endsWith("/e2/send")), "whisperSend posts to /e2/send (forward-private), not /whisper/send");
  ok(!calls.some(c => c.url.includes("/whisper/send")), "the browser never calls the compatibility /whisper/send alias directly");

  calls.length = 0;
  global.fetch = async (url) => { calls.push({ url: String(url), opts: null }); return { ok: true, text: async () => JSON.stringify([{ txid: "aabbcc", text: "hi" }]) }; };
  await t.whisperRecv();
  ok(calls.some(c => c.url.endsWith("/e2/recv")), "inbox polls /e2/recv (decrypted bodies), not /whisper/recv");
  ok(els.get("wInbox").children.length > 0, "inbox renders a delivered E2 message");

  console.log(failed ? `\n${failed} check(s) FAILED` : "\nall checks passed");
  process.exit(failed ? 1 : 0);
}).catch(e => { console.error("join threw:", e.message); process.exit(1); });
