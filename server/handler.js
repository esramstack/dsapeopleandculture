// DSA People & Culture portal: server logic.
// Runs as a Supabase Edge Function (Deno). It uses only web-standard APIs so the
// same file can be tested in Node.
//
// Every request is POST { action, ... } with "Authorization: Bearer <session token>"
// (except login). The service-role key never leaves this function.

const BUCKET = "hr-files";
const SESSION_HOURS = 12;
const MAX_FILE = 25 * 1024 * 1024;
const LOGIN_WINDOW_MIN = 15, LOGIN_MAX_FAILS = 8, LOGIN_MAX_FAILS_ALL = 60;
// OWASP 2023 figure for PBKDF2-HMAC-SHA256. Older records keep their own `iter` and are
// upgraded to this on the next successful sign-in (see login).
const PBKDF2_ITER = 600000;
const PW_MIN = 12, PW_MAX = 256;
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

// Password records: { salt, iter, hash, ver, kdf }.
//   kdf missing (legacy): the password was trimmed and lower-cased before hashing.
//   kdf 2: the password is hashed exactly as typed (case-sensitive).
// Legacy records keep working until the password is next changed, so nobody is locked out.
const KDF_EXACT = 2;
const pwInput = (pw, rec) => (rec && rec.kdf >= KDF_EXACT ? String(pw ?? "") : normPw(pw));
export async function hashPassword(pw, saltB64, iter = PBKDF2_ITER) {
  const base = await crypto.subtle.importKey("raw", te.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromB64(saltB64), iterations: iter }, base, 256);
  return b64(new Uint8Array(bits));
}
async function recordFor(input, ver, kdf) {
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  const rec = { salt, iter: PBKDF2_ITER, hash: await hashPassword(input, salt, PBKDF2_ITER), ver };
  if (kdf) rec.kdf = kdf;
  return rec;
}
export const makePasswordRecord = (pw, ver = 1) => recordFor(String(pw ?? ""), ver, KDF_EXACT);
async function checkPassword(pw, rec) {
  if (!rec || !rec.hash || !rec.salt) return false;
  if (String(pw ?? "").length > PW_MAX) return false;
  const h = await hashPassword(pwInput(pw, rec), rec.salt, rec.iter || 100000);
  return sameBytes(te.encode(h), te.encode(rec.hash));
}
// Same password, same normalisation and version, stronger hash. Sessions stay valid.
const rehash = (pw, rec) => recordFor(pwInput(pw, rec), rec.ver || 1, rec.kdf);

// New passwords: long enough, not an obvious guess. Composition rules are deliberately not required.
const WEAK_WORDS = ["password", "passw0rd", "admin", "administrator", "staff", "people", "culture", "peopleandculture", "hr", "dsa", "dsagroup", "msk", "mskaesthetics", "drsalman", "salman", "drsalmanaesthetics", "aesthetics", "clinic", "welcome", "letmein", "qwerty", "qwertyuiop", "abc", "abcdef", "islamabad", "peshawar", "pakistan", "changeme", "secret", "login", "portal"];
export function passwordProblem(pw) {
  const p = String(pw ?? "");
  if (p.length < PW_MIN) return `Use at least ${PW_MIN} characters. A short phrase of three or four words works well.`;
  if (p.length > PW_MAX) return `Use at most ${PW_MAX} characters.`;
  if (p.trim() !== p) return "Remove spaces from the start and end of the password.";
  const low = p.toLowerCase(), letters = low.replace(/[^a-z]/g, "");
  if (/^(.)\1+$/.test(p) || "0123456789012345678901234567890".includes(p) || "abcdefghijklmnopqrstuvwxyz".includes(low)) return "That password is too easy to guess.";
  // A common word padded with numbers or symbols (e.g. "People123!!!!") is still easy to guess.
  if (WEAK_WORDS.includes(letters) || WEAK_WORDS.some((w) => letters.length % w.length === 0 && letters === w.repeat(letters.length / w.length)) || letters.length < 4) return "That password is too easy to guess. Try a phrase of a few unrelated words.";
  return null;
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
// Fields with a fixed list of values, matching the page's dropdowns. "" means not set.
const ENUMS = {
  employees: { status: ["Active", "Probation", "Notice period", "Former"] },
  announcements: { category: ["General", "Policy update", "Event", "Holiday", "Achievement", "Reminder"], audience: ["All staff", "Islamabad", "Peshawar", "Clinical team", "Non-clinical team", "Management"] },
  documents: { kind: ["Draft", "Letter", "Offer letter", "Warning letter", "KPI sheet", "Memo", "Other"] },
  files: { category: ["Contract", "CNIC / ID", "CV", "Letter", "Policy", "Certificate", "Payroll", "Other"] },
};
const ID_RE = /^[A-Za-z0-9_.:-]{1,120}$/;
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// Uploads: types HR actually needs. Web content (HTML, SVG, scripts) and executables are refused.
const FILE_TYPES = {
  pdf: "application/pdf",
  doc: "application/msword",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xls: "application/vnd.ms-excel",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  csv: "text/csv",
  txt: "text/plain",
  rtf: "application/rtf",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  png: "image/png",
  heic: "image/heic",
  webp: "image/webp",
};
// Browser-reported types that are acceptable for each canonical type (browsers vary, and often send nothing).
const MIME_OK = { "text/csv": ["application/vnd.ms-excel", "text/plain"], "application/rtf": ["text/rtf"], "image/jpeg": ["image/jpg", "image/pjpeg"] };
const INLINE_TYPES = new Set(["application/pdf", "image/jpeg", "image/png", "image/webp"]);
export function fileTypeFor(name, mime) {
  const ext = (String(name).match(/\.([A-Za-z0-9]{1,8})$/) || [])[1]?.toLowerCase();
  const canon = ext && own(FILE_TYPES, ext) ? FILE_TYPES[ext] : null;
  if (!canon) return null;
  const m = String(mime || "").toLowerCase().split(";")[0].trim();
  if (m && m !== "application/octet-stream" && m !== canon && !(MIME_OK[canon] || []).includes(m)) return null;
  return canon;
}

function toRow(col, item) {
  const row = {};
  for (const f of COLS[col].fields) {
    if (item[f] === undefined) continue;
    let v = item[f];
    const allowed = ENUMS[col]?.[f];
    if (allowed && v !== "" && v != null && !allowed.includes(v)) throw new HttpError(400, `That ${f} is not one of the options.`);
    if ((f === "employeeId") && v && !ID_RE.test(String(v))) throw new HttpError(400, "That record reference is not valid.");
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
    // Fail closed: without a real secret, tokens would be forgeable (e.g. signed with "undefined").
    if (typeof secret !== "string" || secret.length < 32) throw new HttpError(500, "The portal is not set up correctly. Please contact People & Culture.");
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
    const expected = await hmac(s.session_secret, body);
    let ok = false; try { ok = sameBytes(fromB64url(sig), expected); } catch { ok = false; }
    if (!ok) throw new HttpError(401, "Your session has ended. Please sign in again.");
    let p; try { p = JSON.parse(new TextDecoder().decode(fromB64url(body))); } catch { throw new HttpError(401, "Your session has ended. Please sign in again."); }
    if (!p || !["admin", "staff"].includes(p.role) || !(p.exp > now())) throw new HttpError(401, "Your session has ended. Please sign in again.");
    if ((s.passwords?.[p.role]?.ver || 1) !== p.pv) throw new HttpError(401, "The password was changed. Please sign in again.");
    if (roles.length && !roles.includes(p.role)) throw new HttpError(403, "Only People & Culture can do that.");
    return p;
  }

  // ---- login throttling ----
  async function tooMany(key, max = LOGIN_MAX_FAILS) {
    const since = new Date(now() - LOGIN_WINDOW_MIN * 60e3).toISOString();
    const rows = await sb(`/rest/v1/hr_login_attempts?select=id&key=eq.${enc(key)}&at=gte.${enc(since)}&limit=${max}`);
    return (rows || []).length >= max;
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
      if (typeof body.password !== "string" || !body.password.trim()) throw new HttpError(400, "Enter the password.");
      // cf-connecting-ip / x-real-ip are set by Supabase's proxy; x-forwarded-for can be faked by the caller.
      const ip = String(req.headers.get("cf-connecting-ip") || req.headers.get("x-real-ip") || req.headers.get("x-forwarded-for") || "unknown").split(",")[0].trim();
      const key = `${role}:${ip}`, all = `${role}:all`;
      if (await tooMany(key)) throw new HttpError(429, `Too many attempts. Please wait ${LOGIN_WINDOW_MIN} minutes and try again.`);
      if (await tooMany(all, LOGIN_MAX_FAILS_ALL)) throw new HttpError(429, `Too many wrong passwords from different places. Sign-in is paused for ${LOGIN_WINDOW_MIN} minutes.`);
      const s = await settings(true);
      const rec = s.passwords?.[role];
      if (!(await checkPassword(body.password, rec))) {
        await Promise.all([fail(key), fail(all)]);
        throw new HttpError(401, "That password is not right.");
      }
      // Quietly strengthen an older hash now that we have the password. Never blocks sign-in.
      if ((rec.iter || 100000) < PBKDF2_ITER) {
        try { await setSetting("passwords", { ...s.passwords, [role]: await rehash(body.password, rec) }); } catch { /* keep the old hash */ }
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
      if (typeof ch !== "object" || Array.isArray(ch)) throw new HttpError(400, "Unknown record type.");
      for (const col of Object.keys(ch)) {
        const conf = own(COLS, col) ? COLS[col] : null; if (!conf) throw new HttpError(400, "Unknown record type.");
        const up = ch[col]?.upsert || [], rm = ch[col]?.remove || [];
        if (!Array.isArray(up) || !Array.isArray(rm)) throw new HttpError(400, "Unknown record type.");
        // Validate the whole batch before writing anything.
        for (const item of up) if (item && item.id && (typeof item !== "object" || !ID_RE.test(String(item.id)))) throw new HttpError(400, "That record reference is not valid.");
        for (const id of rm) if (!ID_RE.test(String(id))) throw new HttpError(400, "That record reference is not valid.");
        for (const item of up) if (item && item.id) toRow(col, item);
      }
      for (const col of Object.keys(ch)) {
        const conf = COLS[col];
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
      // New passwords are kept exactly as typed (case-sensitive).
      const na = typeof body.newAdmin === "string" ? body.newAdmin : "", ns = typeof body.newStaff === "string" ? body.newStaff : "";
      if (!na && !ns) throw new HttpError(400, "Enter a new password for at least one role.");
      for (const p of [na, ns]) { const why = p && passwordProblem(p); if (why) throw new HttpError(400, why); }
      const finalAdmin = na || null, finalStaff = ns || null;
      // Compared case-insensitively so the two roles can never be one Shift key apart.
      if (finalAdmin && finalStaff && normPw(finalAdmin) === normPw(finalStaff)) throw new HttpError(400, "The two passwords must be different.");
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
      const name = String(body.name || "file").replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 200);
      const type = fileTypeFor(name, body.type);
      if (!type) throw new HttpError(400, "That file type can't be uploaded. Use PDF, Word, Excel, CSV, text, JPG or PNG.");
      const category = String(body.category || "Other");
      if (!ENUMS.files.category.includes(category)) throw new HttpError(400, "That category is not one of the options.");
      if (body.employeeId && !ID_RE.test(String(body.employeeId))) throw new HttpError(400, "That record reference is not valid.");
      const id = newId("file");
      const safe = name.replace(/[^\w.\- ]+/g, "_").replace(/\s+/g, "_").slice(-100) || "file";
      const folder = String(body.employeeId || "general").replace(/[^\w-]/g, "_").slice(0, 80) || "general";
      const path = `${folder}/${id}-${safe}`;
      await sb("/rest/v1/hr_files", { method: "POST", prefer: "return=minimal", body: {
        id, name, path, size, uploaded: false, staff: !!body.staff,
        type, category,
        note: String(body.note || "").slice(0, 500),
        employee_id: String(body.employeeId || "").slice(0, 120),
        employee_name: String(body.employeeName || "").slice(0, 200),
      } });
      const signed = await sb(`/storage/v1/object/upload/sign/${BUCKET}/${encPath(path)}`, { method: "POST", body: {} });
      // The page must upload with this Content-Type, so storage serves the file as the type we checked.
      return { id, uploadUrl: PUBLIC + "/storage/v1" + signed.url, contentType: type };
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
      // Only PDFs and plain images open in the browser; everything else is sent as a download.
      const download = body.download || !INLINE_TYPES.has(String(row.type));
      const url = PUBLIC + "/storage/v1" + signed.signedURL + (download ? `&download=${enc(row.name)}` : "");
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
