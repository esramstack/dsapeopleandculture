// Security regression tests for server/handler.js (the Supabase Edge Function).
// Run: node --test qa/security/server.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHandler, passwordProblem, fileTypeFor } from "../../server/handler.js";
import { seed, fakeFetch, QA } from "./fake-supabase.mjs";

async function setup(opts) {
  const db = await seed(opts), log = [], clock = { t: Date.now() };
  const handle = createHandler({ url: "https://qa.supabase.local", key: "service-role-never-sent", fetch: fakeFetch(db, log), now: () => clock.t });
  const call = async (action, body = {}, token, headers = {}) => {
    const r = await handle(new Request("https://fn.local", { method: "POST", headers: { "Content-Type": "application/json", "cf-connecting-ip": "203.0.113.9", ...headers, ...(token ? { Authorization: "Bearer " + token } : {}) }, body: JSON.stringify({ action, ...body }) }));
    return { status: r.status, body: await r.json(), headers: r.headers };
  };
  const login = async (role, password) => (await call("login", { role, password })).body.token;
  return { db, log, call, login, clock };
}
const b64url = (s) => Buffer.from(s).toString("base64url");
const tokenBody = (t) => JSON.parse(Buffer.from(t.split(".")[0], "base64url").toString());

// ---------- authentication ----------
test("wrong passwords are rejected with one generic message", async () => {
  const { call } = await setup();
  for (const role of ["staff", "admin"]) {
    const r = await call("login", { role, password: "not-the-password" });
    assert.equal(r.status, 401);
    assert.equal(r.body.error, "That password is not right.");
    assert.ok(!r.body.token);
  }
});

test("staff password cannot unlock admin, and the role cannot be anything else", async () => {
  const { call } = await setup();
  assert.equal((await call("login", { role: "admin", password: QA.STAFF_PW })).status, 401);
  assert.equal((await call("login", { role: "superuser", password: QA.ADMIN_PW })).status, 400);
  assert.equal((await call("login", { role: "staff", password: { toString: () => QA.STAFF_PW } })).status, 400);
});

test("editing the role inside a staff token does not give admin access", async () => {
  const { call, login } = await setup();
  const t = await login("staff", QA.STAFF_PW);
  const p = tokenBody(t); p.role = "admin";
  const forged = b64url(JSON.stringify(p)) + "." + t.split(".")[1];
  for (const action of ["data", "sync", "passwords", "file_upload"]) assert.equal((await call(action, {}, forged)).status, 401, action);
  assert.equal((await call("data", {}, b64url(JSON.stringify(p)))).status, 401, "unsigned token");
  assert.equal((await call("data", {}, b64url(JSON.stringify(p)) + ".")).status, 401, "empty signature");
});

test("expired tokens are refused", async () => {
  const db = await seed(); let clock = Date.now();
  const handle = createHandler({ url: "https://qa.supabase.local", key: "k", fetch: fakeFetch(db), now: () => clock });
  const req = (b, t) => handle(new Request("https://fn.local", { method: "POST", headers: t ? { Authorization: "Bearer " + t } : {}, body: JSON.stringify(b) }));
  const t = (await (await req({ action: "login", role: "staff", password: QA.STAFF_PW })).json()).token;
  assert.equal((await req({ action: "data" }, t)).status, 200);
  clock += 13 * 3600e3;
  assert.equal((await req({ action: "data" }, t)).status, 401);
});

test("server fails closed when the session secret is missing", async () => {
  const { db, call } = await setup();
  db.hr_settings = db.hr_settings.filter((r) => r.key !== "session_secret");
  const r = await call("login", { role: "staff", password: QA.STAFF_PW });
  assert.equal(r.status, 500);
  assert.ok(!r.body.token);
  const forged = b64url(JSON.stringify({ role: "admin", pv: 1, exp: Date.now() + 1e6 }));
  assert.notEqual((await call("data", {}, forged + ".AAAA")).status, 200);
});

test("repeated wrong passwords are throttled", async () => {
  const { call } = await setup();
  for (let i = 0; i < 8; i++) await call("login", { role: "admin", password: "wrong-" + i });
  const r = await call("login", { role: "admin", password: QA.ADMIN_PW });
  assert.equal(r.status, 429);
});

// ---------- password storage & migration ----------
test("legacy passwords still work and are re-hashed at 600k iterations on sign-in", async () => {
  const { db, call, login } = await setup();
  const before = db.hr_settings.find((r) => r.key === "passwords").value.staff;
  assert.equal(before.iter, 100000);
  // Legacy semantics preserved: case/whitespace-insensitive until the password is changed.
  assert.ok(await login("staff", "  " + QA.STAFF_PW.toUpperCase() + " "));
  const after = db.hr_settings.find((r) => r.key === "passwords").value.staff;
  assert.equal(after.iter, 600000);
  assert.equal(after.ver, before.ver, "existing sessions are not ended by the upgrade");
  assert.notEqual(after.hash, before.hash);
  assert.notEqual(after.salt, before.salt);
  assert.ok(!after.kdf, "still a legacy-normalised record");
  assert.ok(await login("staff", QA.STAFF_PW));
  assert.equal((await call("login", { role: "staff", password: "wrong" })).status, 401);
});

test("no password or hash ever appears in a response", async () => {
  const { call, login } = await setup();
  const admin = await login("admin", QA.ADMIN_PW);
  const r = JSON.stringify((await call("data", {}, admin)).body);
  for (const s of [QA.ADMIN_PW, QA.STAFF_PW, QA.SECRET, "salt", "hash", "service-role-never-sent", "session_secret"]) assert.ok(!r.includes(s), s);
});

test("new passwords: weak, short and look-alike passwords are refused", async () => {
  const { call, login } = await setup();
  const t = await login("admin", QA.ADMIN_PW);
  const change = (b) => call("passwords", { current: QA.ADMIN_PW, ...b }, t);
  for (const weak of ["short", "password1234", "People123!!!!", "drsalman2026!", "Staff-Staff-Staff", "aaaaaaaaaaaaaa", "123456789012", "  padded phrase words  "]) {
    const r = await change({ newStaff: weak });
    assert.equal(r.status, 400, weak);
  }
  assert.equal((await change({ newAdmin: "Copper Lantern River 42", newStaff: "copper lantern river 42" })).status, 400);
  assert.equal((await call("passwords", { current: "wrong", newStaff: "Copper Lantern River 42" }, t)).status, 400);
  assert.equal(passwordProblem("Copper Lantern River 42"), null);
});

test("new passwords are case-sensitive, and changing one ends that role's sessions", async () => {
  const { db, call, login } = await setup();
  const admin = await login("admin", QA.ADMIN_PW), staffOld = await login("staff", QA.STAFF_PW);
  const r = await call("passwords", { current: QA.ADMIN_PW, newStaff: "Velvet Harbour Tiger 9" }, admin);
  assert.equal(r.status, 200);
  const rec = db.hr_settings.find((x) => x.key === "passwords").value.staff;
  assert.equal(rec.kdf, 2); assert.equal(rec.iter, 600000);
  assert.ok(!JSON.stringify(rec).includes("Velvet"));
  assert.equal((await call("data", {}, staffOld)).status, 401, "old staff session ended");
  assert.equal((await call("login", { role: "staff", password: "velvet harbour tiger 9" })).status, 401, "case matters now");
  assert.equal((await call("login", { role: "staff", password: QA.STAFF_PW })).status, 401, "old password refused");
  assert.ok(await login("staff", "Velvet Harbour Tiger 9"));
  assert.equal((await call("data", {}, admin)).status, 200, "admin session unaffected");
});

// ---------- authorisation: what staff receive ----------
test("staff data contains no private HR information", async () => {
  const { call, login } = await setup();
  const t = await login("staff", QA.STAFF_PW);
  const d = (await call("data", {}, t)).body;
  const raw = JSON.stringify(d);
  for (const m of QA.PRIVATE) assert.ok(!raw.includes(m), "leaked: " + m);
  assert.deepEqual(Object.keys(d.employees[0]).sort(), ["branch", "department", "id", "name", "role"].sort());
  assert.ok(d.files.every((f) => f.staff === true && !("employeeId" in f) && !("path" in f)));
  assert.ok(d.documents.every((x) => x.staff === true && !("employeeId" in x)));
  assert.equal(d.role, "staff");
});

test("staff directory is empty when the directory is switched off", async () => {
  const { db, call, login } = await setup();
  db.hr_settings.find((r) => r.key === "access").value.directory = false;
  const d = (await call("data", {}, await login("staff", QA.STAFF_PW))).body;
  assert.equal(d.employees.length, 0);
});

test("staff cannot call any admin action", async () => {
  const { db, call, login } = await setup();
  const t = await login("staff", QA.STAFF_PW);
  const before = JSON.stringify(db);
  const attempts = [
    ["sync", { changes: { employees: { upsert: [{ id: "emp-qa-1", name: "Hacked" }] } } }],
    ["sync", { access: { directory: true } }],
    ["passwords", { current: QA.STAFF_PW, newStaff: "Velvet Harbour Tiger 9" }],
    ["file_upload", { name: "x.pdf", type: "application/pdf", size: 10 }],
    ["file_confirm", { id: "file-qa-2" }],
    ["file_cancel", { id: "file-qa-2" }],
  ];
  for (const [a, b] of attempts) assert.equal((await call(a, b, t)).status, 403, a);
  assert.equal(JSON.stringify(db), before, "nothing changed");
});

test("staff can open shared files but not private ones", async () => {
  const { db, call, login, clock } = await setup();
  const t = await login("staff", QA.STAFF_PW);
  assert.equal((await call("file_open", { id: "file-qa-2" }, t)).status, 403);
  assert.equal((await call("file_open", { id: "file-qa-1" }, t)).status, 200);
  db.hr_settings.find((r) => r.key === "access").value.documents = false;
  clock.t += 6000; // settings are cached for up to 5 seconds per server instance
  assert.equal((await call("file_open", { id: "file-qa-1" }, t)).status, 403);
});

// ---------- data integrity ----------
test("admin writes are validated before anything is saved", async () => {
  const { db, call, login } = await setup();
  const t = await login("admin", QA.ADMIN_PW);
  const before = JSON.stringify(db.hr_employees);
  const bad = [
    { employees: { upsert: [{ id: "emp-new", name: "A", status: "Boss" }] } },
    { announcements: { upsert: [{ id: "a1", title: "A", audience: "Everyone on earth" }] } },
    { files: { upsert: [{ id: "file-qa-1", category: "Secret" }] } },
    { employees: { upsert: [{ id: '"><img src=x onerror=alert(1)>', name: "A" }] } },
    { employees: { remove: ["emp-qa-1&id=neq.x"] } },
    JSON.parse('{"__proto__": {"upsert": []}}'),
    { constructor: { upsert: [] } },
    { employees: { upsert: [{ id: "emp-ok", name: "Ok" }, { id: "emp-bad", name: "B", status: "nope" }] } },
  ];
  for (const changes of bad) assert.equal((await call("sync", { changes }, t)).status, 400, JSON.stringify(changes));
  assert.equal(JSON.stringify(db.hr_employees), before, "a bad batch writes nothing");
  assert.equal((await call("sync", { changes: { employees: { upsert: [{ id: "emp-ok", name: "Ok", status: "Probation", __proto__x: 1 }] } } }, t)).status, 200);
  assert.ok(!("__proto__x" in db.hr_employees.find((e) => e.id === "emp-ok")), "unknown fields are dropped");
});

// ---------- files ----------
test("only HR document types can be uploaded, with a server-chosen content type", async () => {
  const { db, call, login } = await setup();
  const t = await login("admin", QA.ADMIN_PW);
  const up = (name, type) => call("file_upload", { name, type, size: 100, category: "Contract" }, t);
  for (const [n, ty] of [["a.html", "text/html"], ["a.htm", "text/html"], ["logo.svg", "image/svg+xml"], ["x.js", "text/javascript"], ["x.mjs", ""], ["setup.exe", "application/x-msdownload"], ["noext", ""], ["contract.pdf", "text/html"], ["contract.pdf.html", "application/pdf"]]) {
    assert.equal((await up(n, ty)).status, 400, n);
  }
  assert.equal((await call("file_upload", { name: "c.pdf", type: "application/pdf", size: 26 * 1024 * 1024, category: "Contract" }, t)).status, 400, "too big");
  assert.equal((await call("file_upload", { name: "c.pdf", type: "application/pdf", size: 10, category: "Nope" }, t)).status, 400, "bad category");
  const ok = await up('Employee Contract <Test>.pdf', "");
  assert.equal(ok.status, 200); assert.equal(ok.body.contentType, "application/pdf");
  const row = db.hr_files.find((f) => f.id === ok.body.id);
  assert.equal(row.type, "application/pdf"); assert.equal(row.uploaded, false);
  assert.ok(!/[<>"]/.test(row.path), "storage path is sanitised");
  assert.equal(fileTypeFor("photo.JPG", "image/jpeg"), "image/jpeg");
});

test("files that are not PDFs or images are always sent as downloads", async () => {
  const { call, login } = await setup();
  const t = await login("admin", QA.ADMIN_PW);
  assert.match((await call("file_open", { id: "file-qa-3" }, t)).body.url, /&download=/);
  assert.doesNotMatch((await call("file_open", { id: "file-qa-1" }, t)).body.url, /&download=/);
});

test("responses are not cacheable and errors do not expose internals", async () => {
  const { call } = await setup();
  const r = await call("nope");
  assert.equal(r.status, 400);
  assert.equal(r.headers.get("cache-control"), "no-store");
  assert.equal(r.headers.get("x-content-type-options"), "nosniff");
  const e = await call("data", {}, "garbage");
  assert.equal(e.status, 401);
  assert.ok(!/HMAC|PBKDF2|stack|at \w+ \(/.test(e.body.error));
});
