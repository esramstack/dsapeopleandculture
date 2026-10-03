// DSA People & Culture portal: server logic.
// Runs as a Supabase Edge Function (Deno). It uses only web-standard APIs so the
// same file can be tested in Node.
//
// Every request is POST { action, ... } with "Authorization: Bearer <session token>"
// (except login). The service-role key never leaves this function.

const BUCKET = "hr-files";
const SESSION_HOURS = 12;
const MAX_FILE = 25 * 1024 * 1024;
const LOGIN_WINDOW_MIN = 15, LOGIN_MAX_FAILS = 8;
const PBKDF2_ITER = 100000;
const DEFAULT_ACCESS = { announcements: true, policies: true, documents: true, directory: false, agent: true };

const te = new TextEncoder();
const b64url = (u8) => btoa(String.fromCharCode(...u8)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64url = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const b64 = (u8) => { let t = ""; for (let i = 0; i < u8.length; i += 32768) t += String.fromCharCode.apply(null, u8.subarray(i, i + 32768)); return btoa(t); };
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const normPw = (p) => String(p ?? "").trim().toLowerCase();
const enc = encodeURIComponent;
const snake = (k) => k.replace(/[A-Z]/g, (m) => "_" + m.toLowerCase());
const camel = (k) => k.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
const fromRow = (row) => { const o = {}; for (const [k, v] of Object.entries(row || {})) o[camel(k)] = v; return o; };

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export async function hashPassword(pw, saltB64, iter = PBKDF2_ITER) {
  const base = await crypto.subtle.importKey("raw", te.encode(normPw(pw)), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromB64(saltB64), iterations: iter }, base, 256);
  return b64(new Uint8Array(bits));
}
export async function makePasswordRecord(pw, ver = 1) {
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  return { salt, iter: PBKDF2_ITER, hash: await hashPassword(pw, salt, PBKDF2_ITER), ver };
}
async function checkPassword(pw, rec) {
  if (!rec || !rec.hash) return false;
  const h = await hashPassword(pw, rec.salt, rec.iter || PBKDF2_ITER);
  return sameBytes(te.encode(h), te.encode(rec.hash));
}

// Fields the page may write, per collection.
const COLS = {
  employees: { table: "hr_employees", fields: ["name", "role", "department", "branch", "entity", "status", "type", "joined", "manager", "phone", "email", "notes"], stamp: "updated_at" },
  announcements: { table: "hr_announcements", fields: ["title", "body", "category", "audience", "date", "expires", "pinned", "author", "staff"], stamp: "updated_at" },
  policies: { table: "hr_policies", fields: ["title", "code", "effective", "category", "source", "note", "body", "staff"], stamp: "updated_at" },
  documents: { table: "hr_documents", fields: ["title", "kind", "employeeId", "employeeName", "body", "staff", "createdAt"] },
  files: { table: "hr_files", fields: ["category", "note", "employeeId", "employeeName", "staff"], updateOnly: true },
};
const BOOL = new Set(["pinned", "staff"]);
const REQUIRED = { employees: "name", announcements: "title", policies: "title", documents: "title" };

function toRow(col, item) {
  const row = {};
  for (const f of COLS[col].fields) {
    if (item[f] === undefined) continue;
    let v = item[f];
    if (BOOL.has(f)) v = !!v;
    else if (f === "createdAt") { const d = new Date(v); if (isNaN(d)) continue; v = d.toISOString(); }
    else v = v == null ? "" : String(v).slice(0, f === "body" ? 300000 : f === "notes" ? 20000 : 2000);
    row[snake(f)] = v;
  }
  return row;
}

export function createHandler(cfg) {
  const URL_ = String(cfg.url).replace(/\/+$/, "");
  const PUBLIC = String(cfg.publicUrl || cfg.url).replace(/\/+$/, "");
  const KEY = cfg.key;
  const f = cfg.fetch || fetch;
  const now = cfg.now || (() => Date.now());

  async function sb(path, { method = "GET", body, prefer } = {}) {
    const r = await f(URL_ + path, {
      method,
      headers: { apikey: KEY, Authorization: `Bearer ${KEY}`, "Content-Type": "application/json", ...(prefer ? { Prefer: prefer } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await r.text();
    let data = null; try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    if (!r.ok) {
      console.error("supabase", method, path, r.status, text.slice(0, 300));
      throw new HttpError(502, "The database did not accept the request. Please try again.");
    }
    return data;
  }

  // ---- settings (cached briefly per instance) ----
  let cache = null, cacheAt = 0;
  async function settings(fresh = false) {
    if (!fresh && cache && now() - cacheAt < 5000) return cache;
    const rows = await sb("/rest/v1/hr_settings?select=key,value");
    const m = {}; for (const r of rows || []) m[r.key] = r.value;
    cache = m; cacheAt = now(); return m;
  }
  async function setSetting(key, value) {
    await sb("/rest/v1/hr_settings?on_conflict=key", { method: "POST", body: { key, value, updated_at: new Date(now()).toISOString() }, prefer: "resolution=merge-duplicates,return=minimal" });
    cache = null;
  }

  // ---- sessions ----
  async function hmac(secret, data) {
    const k = await crypto.subtle.importKey("raw", te.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", k, te.encode(data)));
  }
  async function signToken(role) {
    const s = await settings();
    const body = b64url(te.encode(JSON.stringify({ role, pv: s.passwords?.[role]?.ver || 1, exp: now() + SESSION_HOURS * 3600e3 })));
    return body + "." + b64url(await hmac(s.session_secret, body));
  }
  async function session(req, ...roles) {
    const tok = String(req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
    const [body, sig] = tok.split(".");
    if (!body || !sig) throw new HttpError(401, "Please sign in.");
    const s = await settings();
    let ok = false; try { ok = sameBytes(fromB64url(sig), await hmac(s.session_secret, body)); } catch { ok = false; }
    if (!ok) throw new HttpError(401, "Your session has ended. Please sign in again.");
    let p; try { p = JSON.parse(new TextDecoder().decode(fromB64url(body))); } catch { throw new HttpError(401, "Your session has ended. Please sign in again."); }
    if (!p || !["admin", "staff"].includes(p.role) || !(p.exp > now())) throw new HttpError(401, "Your session has ended. Please sign in again.");
    if ((s.passwords?.[p.role]?.ver || 1) !== p.pv) throw new HttpError(401, "The password was changed. Please sign in again.");
    if (roles.length && !roles.includes(p.role)) throw new HttpError(403, "Only People & Culture can do that.");
    return p;
  }

  // ---- login throttling ----
  async function tooMany(key) {
    const since = new Date(now() - LOGIN_WINDOW_MIN * 60e3).toISOString();
    const rows = await sb(`/rest/v1/hr_login_attempts?select=id&key=eq.${enc(key)}&at=gte.${enc(since)}`);
    return (rows || []).length >= LOGIN_MAX_FAILS;
  }
  const fail = (key) => sb("/rest/v1/hr_login_attempts", { method: "POST", body: { key }, prefer: "return=minimal" });

  // ---- what each role may see ----
  const FILE_COLS = "id,name,type,size,category,note,employee_id,employee_name,staff,added_at";
  async function loadAll() {
    const [employees, announcements, policies, documents, files] = await Promise.all([
      sb("/rest/v1/hr_employees?select=*&order=name.asc"),
      sb("/rest/v1/hr_announcements?select=*&order=date.desc"),
      sb("/rest/v1/hr_policies?select=*&order=title.asc"),
      sb("/rest/v1/hr_documents?select=*&order=created_at.desc"),
      sb(`/rest/v1/hr_files?select=${FILE_COLS}&uploaded=is.true&order=added_at.desc`),
    ]);
    return { employees: employees.map(fromRow), announcements: announcements.map(fromRow), policies: policies.map(fromRow), documents: documents.map(fromRow), files: files.map(fromRow) };
  }
  const accessOf = (s) => ({ ...DEFAULT_ACCESS, ...(s.access || {}) });
  const stripPerson = ({ employeeId, employeeName, ...r }) => r;
  function staffView(all, s) {
    const a = accessOf(s);
    return {
      announcements: a.announcements ? all.announcements.filter((x) => x.staff !== false) : [],
      policies: a.policies ? all.policies.filter((x) => x.staff !== false) : [],
      documents: a.documents ? all.documents.filter((x) => x.staff === true).map(stripPerson) : [],
      files: a.documents ? all.files.filter((x) => x.staff === true).map(stripPerson) : [],
      employees: a.directory ? all.employees.filter((e) => e.status !== "Former").map((e) => ({ id: e.id, name: e.name, role: e.role, department: e.department, branch: e.branch })) : [],
    };
  }

  const encPath = (p) => p.split("/").map(enc).join("/");
  async function fileRow(id) {
    const rows = await sb(`/rest/v1/hr_files?select=*&id=eq.${enc(id)}`);
    if (!rows || !rows[0]) throw new HttpError(404, "That file is no longer on record.");
    return rows[0];
  }
  const newId = (p) => `${p}-${now().toString(36)}${b64url(crypto.getRandomValues(new Uint8Array(4))).replace(/[-_]/g, "x").toLowerCase()}`;

  // ---- actions ----
  const actions = {
    async login(req, body) {
      const role = body.role === "admin" ? "admin" : body.role === "staff" ? "staff" : null;
      if (!role) throw new HttpError(400, "Choose Staff or Admin.");
      if (!normPw(body.password)) throw new HttpError(400, "Enter the password.");
      const ip = String(req.headers.get("x-forwarded-for") || req.headers.get("cf-connecting-ip") || "unknown").split(",")[0].trim();
      const key = `${role}:${ip}`;
      if (await tooMany(key)) throw new HttpError(429, `Too many attempts. Please wait ${LOGIN_WINDOW_MIN} minutes and try again.`);
      const s = await settings(true);
      if (!(await checkPassword(body.password, s.passwords?.[role]))) {
        await fail(key);
        throw new HttpError(401, role === "admin" ? "That admin password is not right." : "That password is not right. Ask People & Culture for the staff password.");
      }
      return { token: await signToken(role), role };
    },

    async data(req) {
      const p = await session(req);
      const s = await settings();
      const all = await loadAll();
      const a = accessOf(s);
      const base = { role: p.role, access: a, culture: s.culture || {}, serverTime: new Date(now()).toISOString() };
      if (p.role === "admin") return { ...base, ...all, agentKey: s.agent?.staffKey || "" };
      return { ...base, ...staffView(all, s), agentKey: a.agent ? s.agent?.staffKey || "" : "" };
    },

    // Admin: apply a batch of changes worked out by the page.
    async sync(req, body) {
      await session(req, "admin");
      const ch = body.changes || {};
      const out = { saved: 0, removed: 0 };
      for (const col of Object.keys(ch)) {
        const conf = COLS[col]; if (!conf) throw new HttpError(400, "Unknown record type.");
        for (const item of ch[col].upsert || []) {
          if (!item || !item.id) continue;
          const row = toRow(col, item);
          if (conf.stamp) row[conf.stamp] = new Date(now()).toISOString();
          if (conf.updateOnly) {
            await sb(`/rest/v1/${conf.table}?id=eq.${enc(item.id)}`, { method: "PATCH", body: row, prefer: "return=minimal" });
          } else {
            if (REQUIRED[col] && item[REQUIRED[col]] !== undefined && !String(item[REQUIRED[col]]).trim()) throw new HttpError(400, `Please add a ${REQUIRED[col]}.`);
            row.id = String(item.id).slice(0, 120);
            await sb(`/rest/v1/${conf.table}?on_conflict=id`, { method: "POST", body: row, prefer: "resolution=merge-duplicates,return=minimal" });
            if (col === "employees" && row.name) {
              const patch = { employee_name: row.name };
              await Promise.all([
                sb(`/rest/v1/hr_files?employee_id=eq.${enc(row.id)}`, { method: "PATCH", body: patch, prefer: "return=minimal" }),
                sb(`/rest/v1/hr_documents?employee_id=eq.${enc(row.id)}`, { method: "PATCH", body: patch, prefer: "return=minimal" }),
              ]);
            }
          }
          out.saved++;
        }
        for (const id of ch[col].remove || []) {
          if (col === "files") {
            const rows = await sb(`/rest/v1/hr_files?select=path&id=eq.${enc(id)}`);
            if (rows && rows[0]?.path) await sb(`/storage/v1/object/${BUCKET}`, { method: "DELETE", body: { prefixes: [rows[0].path] } }).catch(() => {});
          }
          await sb(`/rest/v1/${conf.table}?id=eq.${enc(id)}`, { method: "DELETE", prefer: "return=minimal" });
          out.removed++;
        }
      }
      if (body.access && typeof body.access === "object") {
        const a = {}; for (const k of Object.keys(DEFAULT_ACCESS)) a[k] = !!body.access[k];
        await setSetting("access", a);
      }
      if (typeof body.agentKey === "string") await setSetting("agent", { staffKey: body.agentKey.trim().slice(0, 300) });
      return { ok: true, ...out };
    },

    async passwords(req, body) {
      await session(req, "admin");
      const s = await settings(true);
      if (!(await checkPassword(body.current, s.passwords?.admin))) throw new HttpError(400, "The current admin password is not right.");
      const na = normPw(body.newAdmin), ns = normPw(body.newStaff);
      if (!na && !ns) throw new HttpError(400, "Enter a new password for at least one role.");
      if ((na && na.length < 6) || (ns && ns.length < 6)) throw new HttpError(400, "Use at least 6 characters.");
      const finalAdmin = na || null, finalStaff = ns || null;
      if (finalAdmin && finalStaff && finalAdmin === finalStaff) throw new HttpError(400, "The two passwords must be different.");
      if (finalAdmin && !finalStaff && (await checkPassword(finalAdmin, s.passwords?.staff))) throw new HttpError(400, "The admin password must be different from the staff password.");
      if (finalStaff && !finalAdmin && (await checkPassword(finalStaff, s.passwords?.admin))) throw new HttpError(400, "The staff password must be different from the admin password.");
      const next = { ...s.passwords };
      if (finalAdmin) next.admin = await makePasswordRecord(finalAdmin, (s.passwords.admin?.ver || 1) + 1);
      if (finalStaff) next.staff = await makePasswordRecord(finalStaff, (s.passwords.staff?.ver || 1) + 1);
      await setSetting("passwords", next);
      return { ok: true, token: finalAdmin ? await signToken("admin") : undefined };
    },

    async file_upload(req, body) {
      await session(req, "admin");
      const size = Number(body.size) || 0;
      if (size <= 0) throw new HttpError(400, "That file is empty.");
      if (size > MAX_FILE) throw new HttpError(400, "Files can be up to 25 MB.");
      const name = String(body.name || "file").slice(0, 200);
      const id = newId("file");
      const safe = name.replace(/[^\w.\- ]+/g, "_").replace(/\s+/g, "_").slice(-100) || "file";
      const folder = String(body.employeeId || "general").replace(/[^\w-]/g, "_").slice(0, 80) || "general";
      const path = `${folder}/${id}-${safe}`;
      await sb("/rest/v1/hr_files", { method: "POST", prefer: "return=minimal", body: {
        id, name, path, size, uploaded: false, staff: !!body.staff,
        type: String(body.type || "application/octet-stream").slice(0, 120),
        category: String(body.category || "Other").slice(0, 60),
        note: String(body.note || "").slice(0, 500),
        employee_id: String(body.employeeId || "").slice(0, 120),
        employee_name: String(body.employeeName || "").slice(0, 200),
      } });
      const signed = await sb(`/storage/v1/object/upload/sign/${BUCKET}/${encPath(path)}`, { method: "POST", body: {} });
      return { id, uploadUrl: PUBLIC + "/storage/v1" + signed.url };
    },

    async file_confirm(req, body) {
      await session(req, "admin");
      const rows = await sb(`/rest/v1/hr_files?id=eq.${enc(body.id)}`, { method: "PATCH", body: { uploaded: true }, prefer: "return=representation" });
      if (!rows || !rows[0]) throw new HttpError(404, "That upload was not found.");
      const { path, uploaded, ...rest } = rows[0];
      return { file: fromRow(rest) };
    },

    async file_cancel(req, body) {
      await session(req, "admin");
      await sb(`/rest/v1/hr_files?id=eq.${enc(body.id)}&uploaded=is.false`, { method: "DELETE", prefer: "return=minimal" });
      return { ok: true };
    },

    async file_open(req, body) {
      const p = await session(req);
      const row = await fileRow(body.id);
      if (!row.uploaded) throw new HttpError(404, "That file is still uploading or the upload did not finish.");
      if (p.role !== "admin") {
        const s = await settings();
        if (!accessOf(s).documents || row.staff !== true) throw new HttpError(403, "This document is not shared with staff.");
      }
      const signed = await sb(`/storage/v1/object/sign/${BUCKET}/${encPath(row.path)}`, { method: "POST", body: { expiresIn: 300 } });
      const url = PUBLIC + "/storage/v1" + signed.signedURL + (body.download ? `&download=${enc(row.name)}` : "");
      return { url, name: row.name, type: row.type };
    },
  };

  const CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "authorization, content-type, x-client-info, apikey",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Max-Age": "86400",
  };
  const json = (status, obj) => new Response(JSON.stringify(obj), { status, headers: { ...CORS, "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });

  return async function handle(req) {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (req.method !== "POST") return json(405, { error: "Method not allowed." });
    let body = {};
    try { body = await req.json(); } catch { body = {}; }
    const fn = body && typeof body.action === "string" && Object.prototype.hasOwnProperty.call(actions, body.action) ? actions[body.action] : null;
    if (!fn) return json(400, { error: "Unknown request." });
    try { return json(200, await fn(req, body)); }
    catch (e) {
      if (e instanceof HttpError) return json(e.status, { error: e.message });
      console.error(e);
      return json(500, { error: "Something went wrong on the server. Please try again." });
    }
  };
}
