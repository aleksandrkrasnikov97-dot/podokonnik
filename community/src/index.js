// Сервер обоев сообщества Подоконника.
//
// Публичное:
//   GET  /api/list?sort=new|top&q=&offset=&limit=   — обои, которые видят все
//   POST /api/upload            {title, author, kind, size, preview(base64 jpeg)} → {id, token}
//   PUT  /api/upload/:id?t=…    тело — zip с обоями
//   GET  /f/:id.zip | /f/:id.jpg — файл (пока он не перенесён на GitHub)
//   POST /api/dl/:id            — +1 скачивание
//   POST /api/report/:id        {reason} — жалоба (одна от человека на обои)
// Секретов в настройках сервера нет: ключ модератора проверяется по его sha256 (MOD_KEY_SHA256 ниже),
// GitHub Actions подтверждает себя OIDC-токеном GitHub, «соль» для IP сервер придумывает сам.
// Модератор (заголовок X-Mod-Key):
//   GET  /api/mod/check, GET /api/mod/list?filter=reported|hidden|all
//   POST /api/mod/delete/:id, /api/mod/ban/:id (удалить и запретить автору загрузки), /api/mod/keep/:id (снять жалобы)
// GitHub Actions (заголовок Authorization: Bearer <OIDC-токен этого репозитория>):
//   GET /api/sync/pending, POST /api/sync/done {id, file, preview}, POST /api/sync/purged {id}, GET /api/sync/catalog

const MOD_KEY_SHA256 = "ffab344faea7f6d040d2554192c31cfdb8364edaef277b655f45de2bef0258eb";
const GH_REPO = "aleksandrkrasnikov97-dot/podokonnik";
const OIDC_ISS = "https://token.actions.githubusercontent.com";
const OIDC_AUD = "podokonnik-community";
const MAX_FILE = 90 * 1024 * 1024;     // тело запроса на бесплатном плане — до 100 МБ
const MAX_PREVIEW = 600 * 1024;
const CHUNK = 1024 * 1024;             // значение в SQLite Durable Object — до 2 МБ
const UPLOADS_PER_DAY = 10;
const AUTO_HIDE_REPORTS = 5;           // столько жалоб от разных людей — обои прячутся до решения модератора
const KINDS = new Set(["video", "web", "image", "scene"]);
const REASONS = new Set(["nsfw", "violence", "broken", "copyright", "other"]);

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Mod-Key",
  "Access-Control-Max-Age": "86400",
};

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...CORS, ...extra },
  });
}
const fail = (status, error) => json({ ok: false, error }, status);

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    const url = new URL(request.url);
    if (url.pathname === "/" ) return json({ ok: true, name: "Podokonnik community" });
    if (!url.pathname.startsWith("/api/") && !url.pathname.startsWith("/f/")) return fail(404, "not_found");
    const stub = env.HUB.get(env.HUB.idFromName("hub"));
    const res = await stub.fetch(request);
    // кэш браузера и Cloudflare для превью и файлов
    if (url.pathname.startsWith("/f/") && res.status === 200) {
      const h = new Headers(res.headers);
      for (const [k, v] of Object.entries(CORS)) h.set(k, v);
      return new Response(res.body, { status: res.status, headers: h });
    }
    return res;
  },
};

async function sha256(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function rid(n = 10) {
  const a = "abcdefghijkmnpqrstuvwxyz23456789";
  const b = crypto.getRandomValues(new Uint8Array(n));
  return [...b].map(x => a[x % a.length]).join("");
}
function clean(s, max) {
  return String(s ?? "").replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}
function b64bytes(s) {
  const bin = atob(String(s).replace(/^data:[^,]*,/, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function same(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export class Hub {
  constructor(state, env) {
    this.env = env;
    this.sql = state.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS items (
        id TEXT PRIMARY KEY, title TEXT, author TEXT, kind TEXT, size INTEGER DEFAULT 0,
        created INTEGER, downloads INTEGER DEFAULT 0, reports INTEGER DEFAULT 0,
        status TEXT, iph TEXT, token TEXT, gh_file TEXT, gh_preview TEXT, purged INTEGER DEFAULT 0);
      CREATE INDEX IF NOT EXISTS items_status ON items(status, created);
      CREATE TABLE IF NOT EXISTS blobs (key TEXT, n INTEGER, data BLOB, PRIMARY KEY (key, n));
      CREATE TABLE IF NOT EXISTS reports (item TEXT, iph TEXT, reason TEXT, at INTEGER, PRIMARY KEY (item, iph));
      CREATE TABLE IF NOT EXISTS dls (item TEXT, iph TEXT, PRIMARY KEY (item, iph));
      CREATE TABLE IF NOT EXISTS bans (iph TEXT PRIMARY KEY, at INTEGER);
      CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
    `);
    let salt = this.one("SELECT v FROM meta WHERE k = 'salt'");
    if (!salt) {
      salt = { v: rid(32) };
      this.sql.exec("INSERT INTO meta VALUES ('salt', ?)", salt.v);
    }
    this.salt = salt.v;
    this.jwks = null;
  }

  async isGithub(request) {
    const m = /^Bearer (.+)$/.exec(request.headers.get("Authorization") || "");
    if (!m) return false;
    const parts = m[1].split(".");
    if (parts.length !== 3) return false;
    const dec = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), c => c.charCodeAt(0));
    let head, body;
    try { head = JSON.parse(new TextDecoder().decode(dec(parts[0]))); body = JSON.parse(new TextDecoder().decode(dec(parts[1]))); } catch { return false; }
    const now = Date.now() / 1000;
    if (head.alg !== "RS256" || body.iss !== OIDC_ISS || body.aud !== OIDC_AUD || body.repository !== GH_REPO || !(body.exp > now) || !(body.nbf ? body.nbf < now + 60 : true)) return false;
    for (let attempt = 0; attempt < 2; attempt++) {
      if (!this.jwks || attempt) this.jwks = (await (await fetch(OIDC_ISS + "/.well-known/jwks")).json()).keys || [];
      const jwk = this.jwks.find(k => k.kid === head.kid);
      if (!jwk) continue;
      const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
      return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, dec(parts[2]), new TextEncoder().encode(parts[0] + "." + parts[1]));
    }
    return false;
  }

  rows(q, ...a) { return [...this.sql.exec(q, ...a)]; }
  one(q, ...a) { return this.rows(q, ...a)[0]; }

  async fetch(request) {
    try {
      return await this.route(request);
    } catch (e) {
      return fail(500, "server_error");
    }
  }

  async route(request) {
    const url = new URL(request.url);
    const p = url.pathname.split("/").filter(Boolean);   // ["api","list"] / ["f","id.zip"]
    const m = request.method;
    const ip = request.headers.get("CF-Connecting-IP") || "local";
    const iph = await sha256(this.salt + ip);
    const base = url.origin;

    if (p[0] === "f" && m === "GET") return this.file(p[1] || "");
    const a = p[1], id = p[2];

    if (a === "list" && m === "GET") return this.list(url, base);
    if (a === "upload" && m === "POST") return this.uploadStart(request, iph);
    if (a === "upload" && m === "PUT" && id) return this.uploadBody(request, id, url.searchParams.get("t"));
    if (a === "dl" && m === "POST" && id) {
      const r = this.sql.exec("INSERT OR IGNORE INTO dls VALUES (?, ?)", id, iph);
      if (r.rowsWritten) this.sql.exec("UPDATE items SET downloads = downloads + 1 WHERE id = ?", id);
      return json({ ok: true });
    }
    if (a === "report" && m === "POST" && id) return this.report(request, id, iph);

    if (a === "mod") {
      if (!same(await sha256(request.headers.get("X-Mod-Key") || ""), MOD_KEY_SHA256)) return fail(403, "not_moderator");
      return this.mod(m, p[2], p[3], url, base);
    }
    if (a === "sync") {
      if (!(await this.isGithub(request))) return fail(403, "forbidden");
      return this.sync(m, p[2], request, base);
    }
    return fail(404, "not_found");
  }

  view(r, base, mod = false) {
    const o = {
      id: r.id, title: r.title, author: r.author, kind: r.kind, size: r.size, created: r.created,
      downloads: r.downloads,
      preview: r.gh_preview || `${base}/f/${r.id}.jpg`,
      file: r.gh_file || `${base}/f/${r.id}.zip`,
    };
    if (mod) {
      o.status = r.status;
      o.reports = r.reports;
      o.reasons = Object.fromEntries(this.rows("SELECT reason, COUNT(*) n FROM reports WHERE item = ? GROUP BY reason", r.id).map(x => [x.reason, x.n]));
      o.author_id = String(r.iph || "").slice(0, 8);
      o.banned = !!this.one("SELECT 1 x FROM bans WHERE iph = ?", r.iph);
    }
    return o;
  }

  list(url, base) {
    const sort = url.searchParams.get("sort") === "top" ? "downloads DESC, created DESC" : "created DESC";
    const q = clean(url.searchParams.get("q"), 60).toLowerCase();
    const off = Math.max(0, Math.min(100000, parseInt(url.searchParams.get("offset")) || 0));
    const lim = Math.max(1, Math.min(100, parseInt(url.searchParams.get("limit")) || 48));
    const where = "status = 'visible'" + (q ? " AND (lower(title) LIKE ?1 OR lower(author) LIKE ?1)" : "");
    const args = q ? [`%${q.replace(/[%_]/g, "")}%`] : [];
    const total = this.one(`SELECT COUNT(*) n FROM items WHERE ${where}`, ...args).n;
    const items = this.rows(`SELECT * FROM items WHERE ${where} ORDER BY ${sort} LIMIT ${lim} OFFSET ${off}`, ...args).map(r => this.view(r, base));
    return json({ ok: true, total, items });
  }

  async uploadStart(request, iph) {
    if (this.one("SELECT 1 x FROM bans WHERE iph = ?", iph)) return fail(403, "banned");
    this.cleanupStale();
    const day = Date.now() - 86400000;
    if (this.one("SELECT COUNT(*) n FROM items WHERE iph = ? AND created > ?", iph, day).n >= UPLOADS_PER_DAY) return fail(429, "too_many");
    let b;
    try { b = await request.json(); } catch { return fail(400, "bad_json"); }
    const title = clean(b.title, 80), author = clean(b.author, 40) || "Аноним";
    const kind = KINDS.has(b.kind) ? b.kind : "video";
    const size = Number(b.size) || 0;
    if (!title) return fail(400, "no_title");
    if (size <= 0 || size > MAX_FILE) return fail(413, "too_big");
    const prev = b.preview ? b64bytes(b.preview) : null;
    if (!prev || prev.length < 100 || prev.length > MAX_PREVIEW || prev[0] !== 0xff || prev[1] !== 0xd8) return fail(400, "bad_preview");
    let id;
    do id = rid(); while (this.one("SELECT 1 x FROM items WHERE id = ?", id));
    const token = rid(24);
    this.sql.exec("INSERT INTO items (id, title, author, kind, size, created, status, iph, token) VALUES (?, ?, ?, ?, ?, ?, 'uploading', ?, ?)",
      id, title, author, kind, size, Date.now(), iph, token);
    this.sql.exec("INSERT INTO blobs VALUES (?, 0, ?)", id + ".jpg", prev);
    return json({ ok: true, id, token, max: MAX_FILE });
  }

  async uploadBody(request, id, token) {
    const it = this.one("SELECT * FROM items WHERE id = ?", id);
    if (!it || it.status !== "uploading" || !same(token || "", it.token || "")) return fail(403, "bad_token");
    if (!request.body) return fail(400, "empty");
    const key = id + ".zip";
    this.sql.exec("DELETE FROM blobs WHERE key = ?", key);
    const reader = request.body.getReader();
    let buf = new Uint8Array(CHUNK), fill = 0, n = 0, total = 0, head = null;
    const flush = () => {
      if (!fill) return;
      this.sql.exec("INSERT INTO blobs VALUES (?, ?, ?)", key, n++, buf.slice(0, fill));
      fill = 0;
    };
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!head) head = value.slice(0, 4);
      total += value.length;
      if (total > MAX_FILE) {
        reader.cancel().catch(() => {});
        this.dropItem(id);
        return fail(413, "too_big");
      }
      let off = 0;
      while (off < value.length) {
        const take = Math.min(CHUNK - fill, value.length - off);
        buf.set(value.subarray(off, off + take), fill);
        fill += take; off += take;
        if (fill === CHUNK) flush();
      }
    }
    flush();
    if (!total || !head || head[0] !== 0x50 || head[1] !== 0x4b) {   // "PK" — zip
      this.dropItem(id);
      return fail(400, "not_zip");
    }
    this.sql.exec("UPDATE items SET status = 'visible', size = ?, token = NULL, created = ? WHERE id = ?", total, Date.now(), id);
    return json({ ok: true, id });
  }

  file(name) {
    const mm = /^([a-z0-9]{6,16})\.(zip|jpg)$/.exec(name);
    if (!mm) return fail(404, "not_found");
    const [, id, ext] = mm;
    const it = this.one("SELECT * FROM items WHERE id = ?", id);
    if (!it || it.status === "deleted" || (it.status === "uploading" && ext === "zip")) return fail(404, "not_found");
    const gh = ext === "zip" ? it.gh_file : it.gh_preview;
    if (gh) return Response.redirect(gh, 302);
    const key = name;
    const parts = this.rows("SELECT n, length(data) len FROM blobs WHERE key = ? ORDER BY n", key);
    if (!parts.length) return fail(404, "not_found");
    const total = parts.reduce((s, x) => s + x.len, 0);
    let i = 0;
    const sql = this.sql;
    const stream = new ReadableStream({
      pull(c) {
        if (i >= parts.length) { c.close(); return; }
        const r = [...sql.exec("SELECT data FROM blobs WHERE key = ? AND n = ?", key, parts[i++].n)][0];
        c.enqueue(new Uint8Array(r.data));
      },
    });
    return new Response(stream, {
      headers: {
        "Content-Type": ext === "zip" ? "application/zip" : "image/jpeg",
        "Content-Length": String(total),
        "Cache-Control": ext === "jpg" ? "public, max-age=86400" : "no-store",
        ...(ext === "zip" ? { "Content-Disposition": `attachment; filename="${id}.zip"` } : {}),
      },
    });
  }

  async report(request, id, iph) {
    const it = this.one("SELECT status FROM items WHERE id = ?", id);
    if (!it || it.status === "deleted") return fail(404, "not_found");
    let b = {};
    try { b = await request.json(); } catch {}
    const reason = REASONS.has(b.reason) ? b.reason : "other";
    this.sql.exec("INSERT OR REPLACE INTO reports VALUES (?, ?, ?, ?)", id, iph, reason, Date.now());
    const n = this.one("SELECT COUNT(*) n FROM reports WHERE item = ?", id).n;
    this.sql.exec("UPDATE items SET reports = ? WHERE id = ?", n, id);
    if (n >= AUTO_HIDE_REPORTS && it.status === "visible") this.sql.exec("UPDATE items SET status = 'hidden' WHERE id = ?", id);
    return json({ ok: true });
  }

  dropItem(id) {
    this.sql.exec("DELETE FROM blobs WHERE key = ? OR key = ?", id + ".zip", id + ".jpg");
    this.sql.exec("UPDATE items SET status = 'deleted', token = NULL WHERE id = ?", id);
  }

  cleanupStale() {
    const old = Date.now() - 3600000;
    for (const r of this.rows("SELECT id FROM items WHERE status = 'uploading' AND created < ?", old)) this.dropItem(r.id);
  }

  mod(m, action, id, url, base) {
    if (action === "check") return json({ ok: true });
    if (action === "list" && m === "GET") {
      const f = url.searchParams.get("filter");
      const where = f === "hidden" ? "status = 'hidden'" : f === "all" ? "status IN ('visible','hidden')" : "status IN ('visible','hidden') AND reports > 0";
      const items = this.rows(`SELECT * FROM items WHERE ${where} ORDER BY reports DESC, created DESC LIMIT 500`).map(r => this.view(r, base, true));
      const counts = {
        reported: this.one("SELECT COUNT(*) n FROM items WHERE status IN ('visible','hidden') AND reports > 0").n,
        hidden: this.one("SELECT COUNT(*) n FROM items WHERE status = 'hidden'").n,
        all: this.one("SELECT COUNT(*) n FROM items WHERE status IN ('visible','hidden')").n,
      };
      return json({ ok: true, items, counts });
    }
    if (m !== "POST" || !id) return fail(404, "not_found");
    const it = this.one("SELECT * FROM items WHERE id = ?", id);
    if (!it) return fail(404, "not_found");
    if (action === "delete" || action === "ban") {
      this.dropItem(id);
      if (action === "ban" && it.iph) {
        this.sql.exec("INSERT OR IGNORE INTO bans VALUES (?, ?)", it.iph, Date.now());
        for (const r of this.rows("SELECT id FROM items WHERE iph = ? AND status != 'deleted'", it.iph)) this.dropItem(r.id);
      }
      return json({ ok: true });
    }
    if (action === "keep") {
      this.sql.exec("DELETE FROM reports WHERE item = ?", id);
      this.sql.exec("UPDATE items SET reports = 0, status = CASE WHEN status = 'hidden' THEN 'visible' ELSE status END WHERE id = ?", id);
      return json({ ok: true });
    }
    if (action === "unban" && it.iph) {
      this.sql.exec("DELETE FROM bans WHERE iph = ?", it.iph);
      return json({ ok: true });
    }
    return fail(404, "not_found");
  }

  async sync(m, action, request, base) {
    if (action === "pending" && m === "GET") {
      const upload = this.rows("SELECT id FROM items WHERE status IN ('visible','hidden') AND gh_file IS NULL").map(r => r.id);
      const purge = this.rows("SELECT id FROM items WHERE status = 'deleted' AND purged = 0 AND gh_file IS NOT NULL").map(r => r.id);
      return json({ ok: true, upload, purge });
    }
    if (action === "catalog" && m === "GET") {
      const items = this.rows("SELECT * FROM items WHERE status = 'visible' AND gh_file IS NOT NULL ORDER BY created DESC").map(r => this.view(r, base));
      return json({ ok: true, api: base, updated: Date.now(), items });
    }
    if (m !== "POST") return fail(404, "not_found");
    const b = await request.json();
    if (action === "done") {
      const ok = u => typeof u === "string" && u.startsWith("https://github.com/");
      if (!ok(b.file) || !ok(b.preview)) return fail(400, "bad_url");
      const it = this.one("SELECT status FROM items WHERE id = ?", b.id);
      if (!it) return fail(404, "not_found");
      this.sql.exec("UPDATE items SET gh_file = ?, gh_preview = ? WHERE id = ?", b.file, b.preview, b.id);
      this.sql.exec("DELETE FROM blobs WHERE key = ? OR key = ?", b.id + ".zip", b.id + ".jpg");
      return json({ ok: true, deleted: it.status === "deleted" });
    }
    if (action === "purged") {
      this.sql.exec("UPDATE items SET purged = 1 WHERE id = ?", b.id);
      return json({ ok: true });
    }
    return fail(404, "not_found");
  }
}
