// In-memory stand-in for the parts of Supabase (PostgREST + Storage) that server/handler.js uses.
// Lets the real handler run locally against throwaway QA data. Never talks to the live project.
import { hashPassword } from "../../server/handler.js";

const b64 = (u8) => Buffer.from(u8).toString("base64");
export const QA = {
  ADMIN_PW: "QA-Legacy-Admin-pass",   // legacy record: matched after trim + lower-case
  STAFF_PW: "QA-Legacy-Staff-pass",
  SECRET: "qa-session-secret-".padEnd(96, "x"),
  // Markers that must never reach a staff browser.
  PRIVATE: ["QA-PRIVATE-PHONE-0300", "qa.private@example.com", "QA-PRIVATE-NOTE", "QA Former Employee", "QA Hidden Announcement", "QA Hidden Policy", "QA Private Letter", "QA-CNIC-private.pdf", "QA-PRIVATE-FILE-NOTE"],
  XSS: '<img src=x onerror="window.__xss=(window.__xss||0)+1">',
};

async function legacyRecord(pw, ver) {
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  return { salt, iter: 100000, hash: await hashPassword(String(pw).trim().toLowerCase(), salt, 100000), ver };
}

export async function seed({ xss = false } = {}) {
  const X = xss ? QA.XSS : "";
  const now = new Date().toISOString();
  return {
    hr_settings: [
      { key: "session_secret", value: QA.SECRET },
      { key: "passwords", value: { admin: await legacyRecord(QA.ADMIN_PW, 1), staff: await legacyRecord(QA.STAFF_PW, 1) } },
      { key: "access", value: { announcements: true, policies: true, documents: true, directory: true, agent: false } },
      { key: "culture", value: {} },
    ],
    hr_employees: [
      { id: "emp-qa-1", name: "QA Security Employee" + X, role: "QA Role" + X, department: "QA Dept" + X, branch: "Islamabad", entity: "DSA Group", status: "Active", type: "Full-time", joined: "2026-01-01", manager: "QA Manager" + X, phone: "QA-PRIVATE-PHONE-0300", email: "qa.private@example.com", notes: "QA-PRIVATE-NOTE" + X },
      { id: "emp-qa-2", name: "QA Former Employee", role: "Old role", department: "QA Dept", branch: "Peshawar", status: "Former", phone: "QA-PRIVATE-PHONE-0300", email: "qa.private@example.com", notes: "QA-PRIVATE-NOTE" },
    ],
    hr_announcements: [
      { id: "ann-qa-1", title: "QA Security Announcement" + X, body: "Visible body " + X + " javascript:alert(1)", category: "General", audience: "All staff", date: "2026-10-01", pinned: false, author: "QA", staff: true },
      { id: "ann-qa-2", title: "QA Hidden Announcement", body: "Hidden", category: "General", audience: "Management", date: "2026-10-02", pinned: false, author: "QA", staff: false },
    ],
    hr_policies: [
      { id: "pol-qa-1", title: "QA Security Policy" + X, code: "QA-1" + X, effective: "2026", category: "General" + X, source: "QA" + X, note: "Note" + X, body: "Policy body <script>window.__xss=99</script> " + X, staff: true },
      { id: "pol-qa-2", title: "QA Hidden Policy", code: "QA-2", category: "General", body: "Hidden", staff: false },
    ],
    hr_documents: [
      { id: "doc-qa-1", title: "QA Security Document" + X, kind: "Letter", employee_id: "", employee_name: "", body: "Shared doc " + X, staff: true, created_at: now },
      { id: "doc-qa-2", title: "QA Private Letter", kind: "Letter", employee_id: "emp-qa-1", employee_name: "QA Security Employee", body: "Private", staff: false, created_at: now },
    ],
    hr_files: [
      { id: "file-qa-1", name: "QA-shared-form" + (xss ? '"><img src=x onerror="window.__xss=7">' : "") + ".pdf", path: "general/file-qa-1.pdf", type: "application/pdf", size: 1000, category: "Policy", note: "Shared note" + X, employee_id: "", employee_name: "", staff: true, uploaded: true, added_at: now },
      { id: "file-qa-2", name: "QA-CNIC-private.pdf", path: "emp-qa-1/file-qa-2.pdf", type: "application/pdf", size: 1000, category: "CNIC / ID", note: "QA-PRIVATE-FILE-NOTE", employee_id: "emp-qa-1", employee_name: "QA Security Employee", staff: false, uploaded: true, added_at: now },
      { id: "file-qa-3", name: "QA-sheet.docx", path: "general/file-qa-3.docx", type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", size: 1000, category: "Other", note: "", employee_id: "", employee_name: "", staff: true, uploaded: true, added_at: now },
    ],
    hr_login_attempts: [],
  };
}

function match(row, filters) {
  return filters.every(([col, op, val]) => {
    const v = row[col];
    if (op === "eq") return String(v ?? "") === val;
    if (op === "gte") return String(v ?? "") >= val;
    if (op === "is") return val === "true" ? v === true : val === "false" ? v === false : v == null;
    throw new Error("fake supabase: unsupported op " + op);
  });
}

// Returns a fetch() that serves the given db object. `log` records every call for assertions.
export function fakeFetch(db, log = []) {
  let seq = 0;
  return async (url, init = {}) => {
    const u = new URL(url), method = init.method || "GET";
    const body = init.body ? JSON.parse(init.body) : undefined;
    log.push({ method, path: u.pathname, body });
    const json = (status, obj) => new Response(obj === undefined ? "" : JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
    if (u.pathname.startsWith("/storage/v1/")) {
      const rest = u.pathname.slice("/storage/v1".length);
      if (rest.startsWith("/object/upload/sign/")) return json(200, { url: rest.replace("/object/upload/sign/", "/object/upload/sign/") + "?token=qa" });
      if (rest.startsWith("/object/sign/")) return json(200, { signedURL: rest + "?token=qa" });
      if (method === "DELETE") return json(200, []);
      return json(404, { error: "not found" });
    }
    const table = u.pathname.replace("/rest/v1/", "");
    if (!db[table]) return json(404, { message: "no table " + table });
    const filters = [], params = {};
    for (const [k, v] of u.searchParams) {
      if (["select", "order", "limit", "on_conflict"].includes(k)) params[k] = v;
      else { const i = v.indexOf("."); filters.push([k, v.slice(0, i), v.slice(i + 1)]); }
    }
    const prefer = init.headers?.Prefer || "";
    const pick = (r) => { if (!params.select || params.select === "*") return { ...r }; const o = {}; for (const c of params.select.split(",")) o[c] = r[c]; return o; };
    if (method === "GET") {
      let rows = db[table].filter((r) => match(r, filters));
      if (params.limit) rows = rows.slice(0, +params.limit);
      return json(200, rows.map(pick));
    }
    if (method === "POST") {
      const items = Array.isArray(body) ? body : [body];
      for (const it of items) {
        const key = params.on_conflict;
        const row = { ...it };
        if (table === "hr_login_attempts") { row.id = ++seq; row.at = new Date().toISOString(); }
        if (table === "hr_files" && !row.added_at) row.added_at = new Date().toISOString();
        const i = key ? db[table].findIndex((r) => r[key] === row[key]) : -1;
        if (i >= 0) db[table][i] = { ...db[table][i], ...row }; else db[table].push(row);
      }
      return json(201, prefer.includes("representation") ? items : undefined);
    }
    if (method === "PATCH") {
      const rows = db[table].filter((r) => match(r, filters));
      for (const r of rows) Object.assign(r, body);
      return json(200, prefer.includes("representation") ? rows.map((r) => ({ ...r })) : undefined);
    }
    if (method === "DELETE") {
      db[table] = db[table].filter((r) => !match(r, filters));
      return json(204);
    }
    return json(405, {});
  };
}
