// Browser security regression tests for index.html, run against the real server handler and
// throwaway QA data (fake-supabase.mjs). The page is served with the headers from vercel.json,
// so the Content-Security-Policy is enforced exactly as in production.
// Run: node qa/security/browser.test.mjs         (needs: cd qa/security && npm install)
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, firefox, webkit } from "playwright";
import { createHandler } from "../../server/handler.js";
import { seed, fakeFetch, QA } from "./fake-supabase.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const API = "https://ioqvezimbrdaojbwsfbf.supabase.co";
const HEADERS = JSON.parse(fs.readFileSync(path.join(ROOT, "vercel.json"), "utf8")).headers.flatMap((r) => r.headers);

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; console.log((cond ? "  ✔ " : "  ✖ ") + name); };
const sec = (t) => console.log("\n" + t);

// ---- static site with production headers ----
const site = http.createServer((req, res) => {
  const f = path.join(ROOT, req.url === "/" || req.url.startsWith("/#") ? "index.html" : decodeURIComponent(req.url.split("?")[0]));
  if (!f.startsWith(ROOT) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end(); }
  const h = { "Content-Type": f.endsWith(".html") ? "text/html; charset=utf-8" : f.endsWith(".png") ? "image/png" : "application/octet-stream" };
  for (const x of HEADERS) h[x.key] = x.value;
  res.writeHead(200, h); res.end(fs.readFileSync(f));
});
await new Promise((r) => site.listen(0, "127.0.0.1", r));
const SITE = `http://127.0.0.1:${site.address().port}/`;

async function newWorld(browserType, opts = {}) {
  const db = await seed(opts), log = [];
  const handle = createHandler({ url: API, key: "service-role-never-sent", fetch: fakeFetch(db, log) });
  const browser = await browserType.launch();
  const ctx = await browser.newContext(opts.mobile ? { viewport: { width: 390, height: 844 }, isMobile: browserType !== firefox, hasTouch: true } : {});
  const calls = [];
  await ctx.route(API + "/**", async (route) => {
    const req = route.request(), u = new URL(req.url());
    if (u.pathname === "/functions/v1/hr-portal") {
      const body = req.postData() || "";
      try { calls.push(JSON.parse(body).action); } catch {}
      const r = await handle(new Request(req.url(), { method: req.method(), headers: req.headers(), body: req.method() === "POST" ? body : undefined }));
      return route.fulfill({ status: r.status, headers: Object.fromEntries(r.headers), body: await r.text() });
    }
    if (u.pathname.startsWith("/storage/v1/object/upload/sign/")) return route.fulfill({ status: 200, headers: { "Access-Control-Allow-Origin": "*" }, body: "{}" });
    if (u.pathname.startsWith("/storage/v1/object/sign/")) return route.fulfill({ status: 200, contentType: "application/pdf", body: "%PDF-1.4 QA" });
    return route.fulfill({ status: 404, body: "" });
  });
  await ctx.route(/fonts\.(googleapis|gstatic)\.com/, (r) => r.fulfill({ status: 200, body: "" }));
  const page = await ctx.newPage();
  const problems = [];
  page.on("console", (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) problems.push(m.text()); });
  page.on("pageerror", (e) => problems.push("pageerror: " + e.message));
  return { db, browser, ctx, page, calls, problems };
}

async function login(page, role, pw) {
  await page.goto(SITE);
  await page.click(`[data-role="${role}"]`);
  await page.fill("#pw", pw);
  await page.click("#signBtn");
  await page.waitForFunction(() => !document.querySelector("#app").hidden || document.querySelector("#pwErr").textContent, null, { timeout: 15000 });
  await page.waitForTimeout(150);
  return page.locator("#app").isVisible();
}
const html = (page) => page.evaluate(() => document.documentElement.outerHTML);
const leaks = (s) => QA.PRIVATE.filter((m) => s.includes(m));
const visitAll = async (page) => {
  let all = "";
  for (const t of await page.$$eval("#nav button[data-tab]", (b) => b.map((x) => x.dataset.tab))) {
    if (t === "agent") continue;
    await page.evaluate((x) => document.querySelector(`#nav button[data-tab="${x}"]`).click(), t); await page.waitForTimeout(80);
    all += await html(page);
  }
  return all;
};
async function search(page, q) {
  await page.evaluate(() => document.querySelector("#searchBtn").click());
  await page.fill("#gq", q); await page.waitForTimeout(150);
  const t = await page.$eval("#gres", (e) => e.innerHTML);
  await page.keyboard.press("Escape");
  return t;
}

async function run(browserType, name) {
  console.log(`\n================ ${name} ================`);

  sec("Authentication");
  {
    const { page, browser } = await newWorld(browserType);
    ok("wrong staff password rejected", !(await login(page, "staff", "nope-nope-nope")));
    ok("generic error message", (await page.textContent("#pwErr")).trim() === "That password is not right.");
    ok("wrong admin password rejected", !(await login(page, "admin", "nope-nope-nope")));
    ok("staff password cannot open admin", !(await login(page, "admin", QA.STAFF_PW)));
    ok("no token stored after failed sign-in", !(await page.evaluate(() => sessionStorage.length + localStorage.length)));
    await browser.close();
  }

  sec("Staff isolation");
  {
    const { page, browser, calls, problems } = await newWorld(browserType);
    ok("staff signs in", await login(page, "staff", QA.STAFF_PW));
    const dom = await visitAll(page);
    ok("no private data anywhere in the staff DOM (all tabs): " + leaks(dom).join(", "), leaks(dom).length === 0);
    ok("app state is not reachable from DevTools globals", await page.evaluate(() => typeof window.S === "undefined" && typeof window.isAdmin === "undefined" && typeof window.persist === "undefined"));
    ok("settings button hidden", await page.locator("#settingsBtn").isHidden());
    ok("quick add hidden", await page.locator("#quickAdd").isHidden());
    await page.evaluate(() => { document.querySelector("#settingsBtn").hidden = false; document.querySelector("#settingsBtn").click(); document.querySelector("#quickAdd").hidden = false; document.querySelector("#quickAdd").click(); });
    await page.waitForTimeout(200);
    ok("un-hiding and clicking Settings / Quick add opens nothing", !(await page.evaluate(() => document.querySelector("#dlg").open)) && !(await page.$(".pop-menu, [role=menu]")));
    await page.evaluate(() => { location.hash = "#people"; }); await page.waitForTimeout(150);
    for (const h of ["#settings", "#files", "#records"]) { await page.evaluate((x) => { location.hash = x; }, h); await page.waitForTimeout(80); }
    ok("hash changes reveal nothing private", leaks(await html(page)).length === 0);
    let s = "";
    for (const q of ["QA-PRIVATE", "0300", "qa.private", "CNIC", "Contract", "Payroll", "QA Former", "QA Hidden", "Private Letter", "@"]) s += await search(page, q);
    ok("staff search returns nothing private: " + leaks(s).join(", "), leaks(s).length === 0);
    ok("staff page only made staff calls (login/data)", calls.every((c) => ["login", "data", "file_open"].includes(c)));
    const r = await page.evaluate(async (api) => (await fetch(api + "/functions/v1/hr-portal", { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + sessionStorage.getItem("dsa-po-token") }, body: JSON.stringify({ action: "sync", changes: { employees: { upsert: [{ id: "emp-qa-1", name: "Hacked" }] } } }) })).status, API);
    ok("staff calling the admin API from DevTools is refused (403)", r === 403);
    ok("no CSP violations or script errors: " + problems.join(" | "), problems.length === 0);
    await browser.close();
  }

  sec("Session tampering");
  {
    const { page, browser } = await newWorld(browserType);
    await login(page, "staff", QA.STAFF_PW);
    await page.evaluate(() => {
      const t = sessionStorage.getItem("dsa-po-token"); const [b, sig] = t.split(".");
      const p = JSON.parse(atob(b.replace(/-/g, "+").replace(/_/g, "/"))); p.role = "admin";
      sessionStorage.setItem("dsa-po-token", btoa(JSON.stringify(p)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") + "." + sig);
    });
    await page.reload(); await page.waitForTimeout(500);
    ok("token edited to role=admin is rejected, sign-in shown", await page.locator("#gate").isVisible());
    ok("no admin data after tampering", leaks(await html(page)).length === 0);
    await page.evaluate(() => { localStorage.setItem("role", "admin"); sessionStorage.setItem("role", "admin"); });
    ok("planting role keys in storage does nothing", !(await login(page, "admin", "x-wrong-password")));
    await browser.close();
  }

  sec("Stored XSS (QA records contain script payloads)");
  {
    const { page, browser, problems } = await newWorld(browserType, { xss: true });
    await login(page, "admin", QA.ADMIN_PW);
    await visitAll(page);
    await page.click('#nav button[data-tab="people"]');
    await page.click("[data-emp]"); await page.waitForTimeout(150);
    for (const t of ["Employment", "Documents", "Notes"]) { const b = page.locator("#dlg button", { hasText: t }).first(); if (await b.count()) { await b.click(); await page.waitForTimeout(60); } }
    await page.keyboard.press("Escape");
    await page.click('#nav button[data-tab="documents"]'); await page.waitForTimeout(100);
    await search(page, "QA"); await search(page, "img"); await search(page, '"><svg onload=alert(1)>');
    await page.click('#nav button[data-tab="announcements"]'); await page.waitForTimeout(100);
    ok("no injected script ran (admin)", (await page.evaluate(() => window.__xss)) === undefined);
    ok("payload shown as text", (await page.textContent("#main")).includes("onerror="));
    ok("no live <img src=x> elements created", (await page.$$('img[src="x"]')).length === 0);
    await page.evaluate(() => document.querySelector("#userBtn").click());
    await page.locator("[role=menuitem]", { hasText: "Sign out" }).click(); await page.waitForTimeout(300);
    await login(page, "staff", QA.STAFF_PW); await visitAll(page);
    ok("no injected script ran (staff)", (await page.evaluate(() => window.__xss)) === undefined);
    ok("no script errors: " + problems.filter((p) => !/img|x:/.test(p)).join(" | "), problems.filter((p) => p.startsWith("pageerror")).length === 0);
    await browser.close();
  }

  sec("Logout");
  {
    const { page, browser } = await newWorld(browserType);
    await page.goto("about:blank");
    await login(page, "admin", QA.ADMIN_PW);
    await page.click('#nav button[data-tab="people"]');
    await page.click("[data-emp]"); await page.waitForTimeout(150);
    ok("admin sees private phone in profile", (await html(page)).includes("QA-PRIVATE-PHONE-0300"));
    await page.keyboard.press("Escape");
    await page.evaluate(() => document.querySelector("#userBtn").click());
    await page.locator("[role=menuitem]", { hasText: "Sign out" }).click();
    await page.waitForLoadState("load"); await page.waitForTimeout(300);
    ok("sign-in screen after logout", await page.locator("#gate").isVisible());
    ok("session token removed", !(await page.evaluate(() => sessionStorage.getItem("dsa-po-token"))));
    ok("no private data in DOM after logout", leaks(await html(page)).length === 0);
    await page.goBack().catch(() => {}); await page.waitForTimeout(400);
    await page.goForward().catch(() => {}); await page.waitForTimeout(400);
    const after = page.url().startsWith(SITE) ? await html(page) : "";
    ok("Back/Forward after logout shows no private data", leaks(after).length === 0);
    await browser.close();
  }

  sec("Preview as staff");
  {
    const { page, browser, calls } = await newWorld(browserType);
    await login(page, "admin", QA.ADMIN_PW);
    await page.click("#settingsBtn"); await page.click("#ac-preview"); await page.waitForTimeout(200);
    ok("preview banner shown", await page.locator("#exitPreview").isVisible());
    const dom = await visitAll(page);
    ok("preview DOM has only staff-safe data: " + leaks(dom).join(", "), leaks(dom).length === 0);
    let s = ""; for (const q of ["QA-PRIVATE", "qa.private", "CNIC", "QA Hidden", "Private Letter"]) s += await search(page, q);
    ok("preview search is staff-safe: " + leaks(s).join(", "), leaks(s).length === 0);
    ok("admin buttons gone in preview", (await page.locator("#settingsBtn").isHidden()) && (await page.locator("#quickAdd").isHidden()));
    const before = calls.filter((c) => c === "sync").length;
    await page.evaluate(() => { document.querySelector("#quickAdd").hidden = false; document.querySelector("#quickAdd").click(); });
    await page.waitForTimeout(200);
    ok("no admin action possible in preview", calls.filter((c) => c === "sync").length === before && !(await page.evaluate(() => document.querySelector("#dlg").open)));
    await page.click("#exitPreview"); await page.click('#nav button[data-tab="people"]'); await page.waitForTimeout(100);
    ok("admin data restored after preview", (await html(page)).includes("qa.private@example.com"));
    await browser.close();
  }

  sec("File upload");
  {
    const { page, browser, calls, db } = await newWorld(browserType);
    await login(page, "admin", QA.ADMIN_PW);
    const n = () => calls.filter((c) => c === "file_upload").length;
    for (const [nm, ty] of [["evil.html", "text/html"], ["logo.svg", "image/svg+xml"], ["run.js", "text/javascript"], ["setup.exe", "application/octet-stream"]]) {
      await page.setInputFiles("#filePick", { name: nm, mimeType: ty, buffer: Buffer.from("<script>alert(1)</script>") });
      await page.click('#dlg button[value="save"]'); await page.waitForTimeout(200);
    }
    ok("dangerous types are refused before upload", n() === 0);
    await page.setInputFiles("#filePick", { name: '"><img src=x onerror="window.__xss=5">Contract <Test>.pdf', mimeType: "application/pdf", buffer: Buffer.from("%PDF-1.4 QA") });
    ok("malicious filename shown as text in the upload dialog", (await page.textContent("#dlg")).includes("onerror="));
    await page.click('#dlg button[value="save"]'); await page.waitForTimeout(500);
    ok("PDF uploads", n() === 1 && db.hr_files.some((f) => f.name.includes("Contract <Test>.pdf") && f.uploaded && f.type === "application/pdf" && f.staff === false));
    await page.click('#nav button[data-tab="documents"]'); await page.waitForTimeout(150);
    ok("malicious filename did not execute", (await page.evaluate(() => window.__xss)) === undefined && (await page.textContent("#main")).includes("Contract <Test>.pdf"));
    await browser.close();
  }

  sec("Password change (Settings)");
  {
    const { page, browser, calls } = await newWorld(browserType);
    await login(page, "admin", QA.ADMIN_PW);
    await page.click("#settingsBtn");
    const tryPw = async (cur, a, s) => { await page.fill("#pw-cur", cur); await page.fill("#pw-admin", a); await page.fill("#pw-staff", s); await page.click("#pw-save"); await page.waitForTimeout(400); return page.textContent("#pw-msg"); };
    ok("short password refused", (await tryPw(QA.ADMIN_PW, "", "short")).includes("12 characters"));
    ok("weak password refused", (await tryPw(QA.ADMIN_PW, "", "People123!!!!!")).includes("easy to guess"));
    ok("refused locally without calling the server", !calls.includes("passwords"));
    ok("strong passphrase accepted", (await tryPw(QA.ADMIN_PW, "", "Velvet Harbour Tiger 9")).includes("saved"));
    ok("password fields cleared", (await page.inputValue("#pw-staff")) === "" && (await page.inputValue("#pw-cur")) === "");
    await browser.close();
  }

  sec("Mobile");
  {
    const { page, browser, problems } = await newWorld(browserType, { mobile: true });
    ok("staff signs in on a phone", await login(page, "staff", QA.STAFF_PW));
    ok("no private data on mobile", leaks(await visitAll(page)).length === 0);
    ok("no horizontal scroll", await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1));
    ok("no CSP violations on mobile: " + problems.join(" | "), problems.length === 0);
    await browser.close();
  }
}

const only = process.argv[2];
for (const [bt, nm] of [[chromium, "chromium"], [firefox, "firefox"], [webkit, "webkit"]]) {
  if (only && only !== nm) continue;
  try { await run(bt, nm); }
  catch (e) { if (/Executable doesn't exist|install/i.test(e.message)) console.log(`\n(${nm} not installed, skipped: npx playwright install ${nm})`); else { fail++; console.log("  ✖ crashed: " + e.message); } }
}
site.close();
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
