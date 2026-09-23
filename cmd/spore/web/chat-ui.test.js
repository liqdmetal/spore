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
;globalThis.__t = { lsGet, lsSet, showWelcome, hideWelcome, state, join, whisperSend, whisperRecv, esc, sniffEnvelope, renderCard };
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
  // XSS regression: a hostile room line or sender name must render as text,
  // never as a live <script>/<img onerror> node (stored XSS via public rooms).
  // esc() contract is string-level: every HTML metacharacter becomes an
  // entity, so a hostile room line or sender name can never form a live
  // <script>/<img onerror> node when the string lands in innerHTML.
  const evil = '<img src=x onerror=window.__pwnd=1><script>window.__pwnd=2</script>';
  const out = t.esc(evil);
  if (out.indexOf("<") !== -1 || out.indexOf(">") !== -1 || out.indexOf(evil) !== -1) {
    failed++; console.log("  FAIL: esc() left raw HTML metacharacters: " + out);
  } else {
    console.log("  ok: esc() neutralizes script/img injection (all metachars entity-encoded)");
  }
  if (t.esc("<b>x</b>") !== "&lt;b&gt;x&lt;/b&gt;") {
    failed++; console.log("  FAIL: esc() wrong output for a sender-name injection: " + t.esc("<b>x</b>"));
  } else {
    console.log("  ok: esc() output exact for sender names (entity-encoded)");
  }
  console.log("settlement cards (typed envelopes)");
  // sniffEnvelope: the browser-side backstop for servers that predate the
  // structured card field — raw envelope JSON must never leak as text.
  ok(t.sniffEnvelope("hello") === null, "sniffEnvelope: ordinary text is not an envelope");
  ok(t.sniffEnvelope("{") === null, "sniffEnvelope: invalid JSON is not an envelope");
  ok(t.sniffEnvelope("") === null, "sniffEnvelope: empty text is not an envelope");
  for (const [ty, want] of [["spore/escrow/v1","escrow"],["spore/dex/v1","dex"],["spore/invoice/v1","invoice"],["spore/payment/v1","payment"],["spore/receipt/v1","receipt"]]) {
    const got = t.sniffEnvelope(JSON.stringify({ type: ty }));
    ok(got && got.kind === want, "sniffEnvelope: " + ty + " -> " + want);
  }
  ok(t.sniffEnvelope(JSON.stringify({ type: "spore/unknown/v9" })) === null, "sniffEnvelope: unknown spore type is not a card");

  // renderCard: structured, escaped, classed.
  const ce = t.renderCard({ kind: "escrow", summary: "ESCROW CLAIMED 6b18…: preimage revealed, tx settle-1", direction: "received", amount: "1.2", asset: "dero", txid: "settle-tx-1" });
  ok(ce.className === "wcard escrow", "card gets the semantic class (wcard escrow)");
  ok(ce.innerHTML.includes("escrow"), "card shows the kind badge");
  ok(ce.innerHTML.includes("received"), "card shows the direction");
  ok(ce.innerHTML.includes("1.2 dero"), "card shows the amount chip");
  ok(ce.innerHTML.includes("tx settle-tx-1"), "card shows the settlement txid");
  const hostile = t.renderCard({ kind: "dex", summary: "<img src=x onerror=window.__pwnd=1> DEX SWAPPED", txid: "t" });
  ok(hostile.innerHTML.indexOf("<img") === -1 && hostile.innerHTML.includes("&lt;img"), "card escapes a hostile summary (no live img node)");
  const weird = t.renderCard({ kind: "mystery" });
  ok(weird.className === "wcard mystery", "unknown kinds still class (forward-compat rendering)");
  const noAmt = t.renderCard({ kind: "dex", summary: "DEX SWAPPED tA->tB (pool-settled)" });
  ok(!noAmt.innerHTML.includes("amt"), "pool-settled swap renders no zero amount chip");

  // whisperRecv integration: server-classified card wins, local sniff covers
  // old servers, and ordinary text still renders as a plain wtext line.
  global.fetch = async () => ({ ok: true, text: async () => JSON.stringify([
    { txid: "plain1", text: "just a message" },
    { txid: "card1", text: "{raw json}" , card: { kind: "escrow", summary: "ESCROW REFUNDED 6b18…: expired", direction: "received", amount: "1.2", asset: "dero", txid: "r1" } },
    { txid: "old1", text: JSON.stringify({ type: "spore/dex/v1", action: "swap", pair: "tA->tB", txid: "d1" }) },
  ]) });
  await t.whisperRecv();
  const inbox = els.get("wInbox").children;
  const plainLine = inbox.find(x => x.className === "wline" && x.children.some(c => c.className === "wtext"));
  ok(!!plainLine && plainLine.children.some(c => c.className === "wtext" && c.textContent === "just a message"), "ordinary text still renders as a plain line");
  const cardLine = inbox.find(x => x.className === "wline" && x.children.some(c => c.className === "wcard escrow"));
  ok(!!cardLine && cardLine.children.some(c => c.className === "wcard escrow"), "server card field renders a styled card");
  ok(!cardLine.children.some(c => c.className === "wtext"), "a carded line never renders raw JSON text");
  const oldLine = inbox.find(x => x.className === "wline" && x.children.some(c => c.className === "wcard dex"));
  ok(!!oldLine, "raw envelope JSON from an old server is sniffed into a card, not shown as text");


  console.log(failed ? `\n${failed} check(s) FAILED` : "\nall checks passed");
  process.exit(failed ? 1 : 0);
}).catch(e => { console.error("join threw:", e.message); process.exit(1); });
