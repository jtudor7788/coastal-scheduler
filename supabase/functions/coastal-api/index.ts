// Coastal Cleaning scheduler API (Supabase Edge Function, Deno).
// Auth is handled here (admin password / cleaner PIN -> signed token), so deploy with verify_jwt = false.
// Required secrets: COASTAL_ADMIN_PASSWORD, COASTAL_SESSION_SECRET. SUPABASE_DB_URL is provided automatically.
import postgres from "npm:postgres@3.4.5";
import { createClient } from "npm:@supabase/supabase-js@2";

const ADMIN_PASSWORD = Deno.env.get("COASTAL_ADMIN_PASSWORD") ?? "";
const SECRET = Deno.env.get("COASTAL_SESSION_SECRET") ?? "";
const sql = postgres(Deno.env.get("SUPABASE_DB_URL")!, { prepare: false, max: 3 });

const supa = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
const BUCKET = "clean-media";
const MEDIA_TYPES: Record<string, string> = {
  "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/heic": "heic", "image/heif": "heif",
  "video/mp4": "mp4", "video/quicktime": "mov", "video/webm": "webm",
};
const MEDIA_PATH_RE = /^\d+\/[0-9a-f-]{36}\.[a-z0-9]{3,4}$/;

const CORS = {
  "Access-Control-Allow-Origin": Deno.env.get("COASTAL_ALLOWED_ORIGIN") ?? "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
};
const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { ...CORS, "Content-Type": "application/json" } });
const bad = (msg: string, status = 400, extra: Record<string, unknown> = {}) => json({ error: msg, ...extra }, status);

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;
const toMin = (t: string) => { const [h, m] = t.split(":").map(Number); return h * 60 + m; };
const cleanEnd = (c: any) => toMin(c.start_time) + Math.round(c.duration_hours * 60);
const today = () => new Date().toLocaleDateString("en-CA", { timeZone: "America/New_York" });

// ---- tokens ----
const enc = new TextEncoder();
const b64u = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const hmacKey = () => crypto.subtle.importKey("raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
async function sign(payload: Record<string, unknown>) {
  const body = b64u(enc.encode(JSON.stringify(payload)));
  const mac = b64u(await crypto.subtle.sign("HMAC", await hmacKey(), enc.encode(body)));
  return `${body}.${mac}`;
}
async function verify(token: string | null) {
  if (!token || !SECRET) return null;
  const [body, mac] = token.split(".");
  if (!body || !mac) return null;
  const expect = b64u(await crypto.subtle.sign("HMAC", await hmacKey(), enc.encode(body)));
  if (!safeEq(mac, expect)) return null;
  try {
    const p = JSON.parse(atob(body.replace(/-/g, "+").replace(/_/g, "/")));
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}
function safeEq(a: string, b: string) {
  const x = enc.encode(String(a)), y = enc.encode(String(b));
  if (x.length !== y.length) return false;
  let d = 0; for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

// ---- login throttle (per instance, best effort) ----
const fails = new Map<string, { n: number; t: number }>();
const reqHits = new Map<string, number[]>();
const msgHits = new Map<string, number[]>();
const throttled = (k: string) => { const f = fails.get(k); return !!f && f.n >= 8 && Date.now() - f.t < 600_000; };
const noteFail = (k: string) => { const f = fails.get(k) ?? { n: 0, t: 0 }; fails.set(k, { n: f.n + 1, t: Date.now() }); };

// ---- column fragments ----
const CLEAN_COLS = sql`c.id, c.date::text AS date, to_char(c.start_time,'HH24:MI') AS start_time, c.duration_hours::float AS duration_hours,
  c.client, c.address, c.type, c.notes, c.status, c.cleaner_id, c.contact_name, c.contact_phone, c.contact_email, c.source, c.report_published,
  c.property_id, c.rule_id, c.clock_in, c.clock_out, c.release_note`;
const AVAIL_COLS = sql`a.id, a.cleaner_id, a.date::text AS date, to_char(a.start_time,'HH24:MI') AS start_time, to_char(a.end_time,'HH24:MI') AS end_time, a.note`;

async function mediaFor(cleanId: number) {
  const rows = await sql`SELECT id, kind, path, content_type, size_bytes, caption FROM coastal.clean_media WHERE clean_id = ${cleanId} ORDER BY kind, id`;
  if (!rows.length) return [];
  const { data } = await supa.storage.from(BUCKET).createSignedUrls(rows.map((r: any) => r.path), 3600);
  const urlBy = new Map((data ?? []).map((d: any) => [d.path, d.signedUrl]));
  return rows.map((r: any) => ({
    id: Number(r.id), kind: r.kind, type: String(r.content_type).startsWith("video") ? "video" : "image",
    url: urlBy.get(r.path) ?? null, caption: r.caption ?? "", size_bytes: r.size_bytes ? Number(r.size_bytes) : null,
  }));
}
const ownClean = async (cleanId: string, me: number) =>
  (await sql`SELECT id FROM coastal.cleans WHERE id = ${cleanId} AND cleaner_id = ${me} AND status IN ('assigned','confirmed','done')`)[0];

type Viewer = "admin" | "cleaner" | "client";
async function threadFor(cleanId: number | string, thread: string, viewer: Viewer) {
  // Reading a thread marks the other side's messages as seen.
  await sql`UPDATE coastal.clean_messages SET seen = true WHERE clean_id = ${cleanId} AND thread = ${thread} AND sender != ${viewer} AND NOT seen`;
  return await sql`SELECT id, thread, sender, body, fee_cents, fee_status, created_at FROM coastal.clean_messages
    WHERE clean_id = ${cleanId} AND thread = ${thread} ORDER BY id`;
}
const DEFAULT_TASKS = ["Kitchen: counters, sink, appliances, floor", "Bathrooms: toilet, shower/tub, sink, mirror, floor", "Bedrooms: change linens, dust, vacuum", "Living areas: dust, vacuum/mop", "Empty all trash and replace liners", "Restock towels, soap, toilet paper", "Check for damage or left-behind items (take photos)", "Take AFTER photos / video"];
async function ensureTasks(cleanId: number | string) {
  const [{ n }] = await sql`SELECT count(*)::int AS n FROM coastal.clean_tasks WHERE clean_id = ${cleanId}`;
  if (n === 0) {
    const [p] = await sql`SELECT p.checklist FROM coastal.cleans c JOIN coastal.properties p ON p.id = c.property_id WHERE c.id = ${cleanId}`;
    const lines = String(p?.checklist ?? "").split("\n").map((x) => x.trim()).filter(Boolean).slice(0, 40);
    const list = lines.length ? lines : DEFAULT_TASKS;
    for (let i = 0; i < list.length; i++) await sql`INSERT INTO coastal.clean_tasks (clean_id, label, sort) VALUES (${cleanId}, ${list[i].slice(0, 200)}, ${i})`;
  }
  return await sql`SELECT id, label, done FROM coastal.clean_tasks WHERE clean_id = ${cleanId} ORDER BY sort, id`;
}
async function generateRecurring() {
  await sql`INSERT INTO coastal.cleans (date, start_time, duration_hours, client, address, type, notes, status, contact_name, contact_phone, contact_email, property_id, rule_id, source)
    SELECT d::date, r.start_time, r.duration_hours, r.client, r.address, r.type, r.notes, 'open', r.contact_name, r.contact_phone, r.contact_email, r.property_id, r.id, 'recurring'
    FROM coastal.recurring_rules r, generate_series(greatest(r.start_date, ${today()}::date), ${today()}::date + 42, interval '1 day') d
    WHERE r.active AND (d::date - r.start_date) % (7 * r.every_weeks) = 0 AND (r.end_date IS NULL OR d::date <= r.end_date)
    ON CONFLICT (rule_id, date) WHERE rule_id IS NOT NULL DO NOTHING`;
}
async function fillUsual(me: number, reset = false) {
  const [t] = await sql`SELECT weekdays, to_char(start_time,'HH24:MI') AS st, to_char(end_time,'HH24:MI') AS et, filled_through::text AS ft FROM coastal.availability_templates WHERE cleaner_id = ${me}`;
  if (!t || !t.weekdays.length) return;
  const from = reset || !t.ft ? today() : t.ft;
  await sql`INSERT INTO coastal.availability (cleaner_id, date, start_time, end_time, note)
    SELECT ${me}, d::date, ${t.st}::time, ${t.et}::time, 'usual week'
    FROM generate_series(${from}::date + (CASE WHEN ${reset || !t.ft} THEN 0 ELSE 1 END), ${today()}::date + 28, interval '1 day') d
    WHERE extract(dow FROM d)::int = ANY(string_to_array(${(t.weekdays as number[]).join(",")}, ',')::int[]) AND d::date >= ${today()}::date
    ON CONFLICT (cleaner_id, date) DO NOTHING`;
  await sql`UPDATE coastal.availability_templates SET filled_through = ${today()}::date + 28 WHERE cleaner_id = ${me}`;
}
const clipText = (v: unknown, n: number) => String(v ?? "").trim().slice(0, n);
// Client link works once the report is published, or once Nicole has messaged the owner about this clean.
async function clientClean(t: string) {
  if (!/^[a-f0-9]{64}$/.test(t)) return null;
  const [c] = await sql`SELECT c.id, c.date::text AS date, c.type, c.report_note, c.report_published,
    EXISTS (SELECT 1 FROM coastal.clean_messages mm WHERE mm.clean_id = c.id AND mm.thread = 'client' AND mm.sender = 'admin') AS has_msg
    FROM coastal.cleans c WHERE c.report_token = ${t}`;
  return c && (c.report_published || c.has_msg) ? c : null;
}

async function candidatesFor(clean: any) {
  const avail = await sql`SELECT ${AVAIL_COLS}, cl.name FROM coastal.availability a JOIN coastal.cleaners cl ON cl.id = a.cleaner_id
    WHERE a.date = ${clean.date} AND cl.active`;
  const booked = await sql`SELECT ${CLEAN_COLS} FROM coastal.cleans c WHERE c.date = ${clean.date} AND c.cleaner_id IS NOT NULL
    AND c.status IN ('assigned','confirmed','done') AND c.id != ${clean.id}`;
  const s = toMin(clean.start_time), e = cleanEnd(clean);
  return avail.map((a: any) => {
    const mine = booked.filter((x: any) => Number(x.cleaner_id) === Number(a.cleaner_id));
    const overlap = mine.find((x: any) => toMin(x.start_time) < e && cleanEnd(x) > s);
    const fits = toMin(a.start_time) <= s && toMin(a.end_time) >= e;
    return { cleaner_id: Number(a.cleaner_id), name: a.name, window: `${a.start_time}-${a.end_time}`, note: a.note ?? "",
      fits_window: fits, conflict: overlap ? `${overlap.client} ${overlap.start_time}` : null, jobs_that_day: mine.length };
  }).sort((x: any, y: any) => (Number(!!x.conflict) - Number(!!y.conflict)) || (Number(y.fits_window) - Number(x.fits_window)) || x.jobs_that_day - y.jobs_that_day);
}

function validateClean(b: any) {
  if (!DATE_RE.test(b.date || "")) return "Bad date";
  if (b.start_time && !TIME_RE.test(b.start_time)) return "Bad start time";
  if (!b.client) return "Client / property name required";
  if (b.duration_hours != null && !(b.duration_hours > 0 && b.duration_hours <= 16)) return "Bad duration";
  return null;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (!ADMIN_PASSWORD || !SECRET) return bad("Server not configured (missing secrets)", 503);

  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/(functions\/v1\/)?coastal-api/, "") || "/";
  const method = req.method;
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0] ?? "unknown";
  const body: any = ["POST", "PATCH"].includes(method) ? await req.json().catch(() => ({})) : {};

  try {
    // ---- public ----
    if (path === "/api/health") return json({ ok: true });
    if (path === "/api/cleaners/public" && method === "GET")
      return json(await sql`SELECT id, name FROM coastal.cleaners WHERE active ORDER BY name`);

    if (path === "/api/public/report" && method === "GET") {
      const c = await clientClean(url.searchParams.get("t") ?? "");
      if (!c) return bad("Report not found", 404);
      return json({ date: c.date, type: c.type, published: c.report_published, note: c.report_published ? (c.report_note ?? "") : "",
        media: c.report_published ? await mediaFor(Number(c.id)) : [] });
    }
    if (path === "/api/public/report/messages") {
      const c = await clientClean(method === "GET" ? (url.searchParams.get("t") ?? "") : String(body.t ?? ""));
      if (!c) return bad("Not found", 404);
      if (method === "GET") return json(await threadFor(c.id, "client", "client"));
      if (method === "POST") {
        const text = clipText(body.body, 2000);
        if (!text) return bad("Please type a message");
        const k = "msg:" + ip, now = Date.now();
        const hits = (msgHits.get(k) ?? []).filter((x) => now - x < 3600_000);
        if (hits.length >= 20) return bad("Too many messages. Please call us instead.", 429);
        hits.push(now); msgHits.set(k, hits);
        await sql`INSERT INTO coastal.clean_messages (clean_id, thread, sender, body) VALUES (${c.id}, 'client', 'client', ${text})`;
        return json({ ok: true });
      }
    }
    if (path === "/api/public/report/fee" && method === "POST") {
      const c = await clientClean(String(body.t ?? ""));
      if (!c) return bad("Not found", 404);
      const decision = body.decision === "approved" ? "approved" : body.decision === "declined" ? "declined" : null;
      if (!decision) return bad("Bad decision");
      const [f] = await sql`UPDATE coastal.clean_messages SET fee_status = ${decision}, seen = true
        WHERE id = ${Number(body.message_id) || 0} AND clean_id = ${c.id} AND thread = 'client' AND fee_cents IS NOT NULL AND fee_status = 'pending' RETURNING fee_cents`;
      if (!f) return bad("That request was already answered", 409);
      await sql`INSERT INTO coastal.clean_messages (clean_id, thread, sender, body)
        VALUES (${c.id}, 'client', 'client', ${(decision === "approved" ? "Approved" : "Declined") + " the additional fee of $" + (Number(f.fee_cents) / 100).toFixed(2)})`;
      return json({ ok: true });
    }

    if (path === "/api/public/request" && method === "POST") {
      // Public client intake. Lands as status 'requested'; Nicole must approve before cleaners can see it.
      if (body.website) return json({ ok: true }); // honeypot: bots fill this hidden field
      const k = "req:" + ip;
      const now = Date.now();
      const hits = (reqHits.get(k) ?? []).filter((t) => now - t < 3600_000);
      if (hits.length >= 5) return bad("Too many requests from this connection. Please call us instead.", 429);
      const clip = (v: unknown, n: number) => String(v ?? "").trim().slice(0, n);
      const b = {
        contact_name: clip(body.contact_name, 100), contact_phone: clip(body.contact_phone, 30),
        contact_email: clip(body.contact_email, 120), address: clip(body.address, 200),
        type: clip(body.type, 40) || "Residential", notes: clip(body.notes, 1000),
        date: clip(body.date, 10), start_time: clip(body.start_time, 5) || "10:00",
      };
      if (!b.contact_name) return bad("Please enter your name");
      if (!b.contact_phone && !b.contact_email) return bad("Please enter a phone number or email so we can confirm");
      if (b.contact_email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(b.contact_email)) return bad("That email doesn't look right");
      if (!b.address) return bad("Please enter the address to be cleaned");
      if (!DATE_RE.test(b.date) || b.date < today()) return bad("Please pick a date today or later");
      if (!TIME_RE.test(b.start_time)) return bad("Bad time");
      hits.push(now); reqHits.set(k, hits);
      await sql`INSERT INTO coastal.cleans (date, start_time, duration_hours, client, address, type, notes, status, contact_name, contact_phone, contact_email, source)
        VALUES (${b.date}, ${b.start_time}, 2, ${b.contact_name}, ${b.address}, ${b.type}, ${b.notes}, 'requested', ${b.contact_name}, ${b.contact_phone}, ${b.contact_email}, 'client')`;
      return json({ ok: true });
    }

    if (path === "/api/login/admin" && method === "POST") {
      const k = "admin:" + ip;
      if (throttled(k)) return bad("Too many attempts, try again later", 429);
      if (!safeEq(body.password || "", ADMIN_PASSWORD)) { noteFail(k); return bad("Wrong password", 401); }
      return json({ token: await sign({ role: "admin", exp: Date.now() + 30 * 864e5 }), role: "admin" });
    }
    if (path === "/api/login/cleaner" && method === "POST") {
      const k = "cleaner:" + ip;
      if (throttled(k)) return bad("Too many attempts, try again later", 429);
      const [c] = await sql`SELECT * FROM coastal.cleaners WHERE id = ${Number(body.cleaner_id) || 0} AND active`;
      if (!c || !safeEq(body.pin || "", c.pin)) { noteFail(k); return bad("Wrong name or PIN", 401); }
      return json({ token: await sign({ role: "cleaner", id: Number(c.id), exp: Date.now() + 30 * 864e5 }), role: "cleaner", name: c.name, id: Number(c.id) });
    }

    // ---- auth ----
    const h = req.headers.get("authorization") ?? "";
    const user = await verify(h.startsWith("Bearer ") ? h.slice(7) : null);
    if (!user) return bad("Not signed in", 401);

    // ---- cleaner ----
    if (path.startsWith("/api/me/")) {
      if (user.role !== "cleaner") return bad("Not allowed", 403);
      const me = user.id as number;

      if (path === "/api/me/usual" && method === "GET") {
        const [t] = await sql`SELECT weekdays, to_char(start_time,'HH24:MI') AS start_time, to_char(end_time,'HH24:MI') AS end_time FROM coastal.availability_templates WHERE cleaner_id = ${me}`;
        return json(t ?? { weekdays: [], start_time: "08:00", end_time: "17:00" });
      }
      if (path === "/api/me/usual" && method === "POST") {
        const days = (Array.isArray(body.weekdays) ? body.weekdays : []).map(Number).filter((n: number) => n >= 0 && n <= 6);
        const st = body.start_time || "08:00", et = body.end_time || "17:00";
        if (!TIME_RE.test(st) || !TIME_RE.test(et) || toMin(et) <= toMin(st)) return bad("Bad times");
        await sql`INSERT INTO coastal.availability_templates (cleaner_id, weekdays, start_time, end_time, filled_through) VALUES (${me}, string_to_array(${days.join(",")}, ',')::int[], ${st}, ${et}, NULL)
          ON CONFLICT (cleaner_id) DO UPDATE SET weekdays = EXCLUDED.weekdays, start_time = EXCLUDED.start_time, end_time = EXCLUDED.end_time, filled_through = NULL`;
        await fillUsual(me, true);
        return json({ ok: true });
      }
      if (path === "/api/me/availability" && method === "GET") {
        await fillUsual(me);
        const from = url.searchParams.get("from") || today();
        return json(await sql`SELECT ${AVAIL_COLS} FROM coastal.availability a WHERE a.cleaner_id = ${me} AND a.date >= ${from} ORDER BY a.date`);
      }
      if (path === "/api/me/availability" && method === "POST") {
        const { dates, start_time = "08:00", end_time = "17:00", note = "" } = body;
        if (!Array.isArray(dates) || !dates.length) return bad("Pick at least one date");
        if (!dates.every((d: string) => DATE_RE.test(d))) return bad("Bad date format");
        if (!TIME_RE.test(start_time) || !TIME_RE.test(end_time) || toMin(end_time) <= toMin(start_time)) return bad("Bad times");
        await sql.begin(async (tx) => {
          for (const d of dates) await tx`INSERT INTO coastal.availability (cleaner_id, date, start_time, end_time, note)
            VALUES (${me}, ${d}, ${start_time}, ${end_time}, ${note})
            ON CONFLICT (cleaner_id, date) DO UPDATE SET start_time = EXCLUDED.start_time, end_time = EXCLUDED.end_time, note = EXCLUDED.note`;
        });
        return json({ ok: true, count: dates.length });
      }
      let m = path.match(/^\/api\/me\/availability\/(\d{4}-\d{2}-\d{2})$/);
      if (m && method === "DELETE") {
        const [busy] = await sql`SELECT 1 FROM coastal.cleans WHERE cleaner_id = ${me} AND date = ${m[1]} AND status IN ('assigned','confirmed')`;
        if (busy) return bad("You are assigned a clean that day. Ask Nicole to move it first.", 409);
        await sql`DELETE FROM coastal.availability WHERE cleaner_id = ${me} AND date = ${m[1]}`;
        return json({ ok: true });
      }
      if (path === "/api/me/cleans" && method === "GET") {
        const from = url.searchParams.get("from") || today();
        return json(await sql`SELECT ${CLEAN_COLS},
          (SELECT count(*) FROM coastal.clean_messages mm WHERE mm.clean_id = c.id AND mm.thread = 'crew' AND mm.sender = 'admin' AND NOT mm.seen)::int AS unread,
          (SELECT p.access_info FROM coastal.properties p WHERE p.id = c.property_id) AS access_info,
          (SELECT count(*) FROM coastal.clean_tasks t WHERE t.clean_id = c.id)::int AS tasks_total,
          (SELECT count(*) FROM coastal.clean_tasks t WHERE t.clean_id = c.id AND t.done)::int AS tasks_done
          FROM coastal.cleans c WHERE c.cleaner_id = ${me} AND c.date >= ${from}
          AND c.status != 'cancelled' ORDER BY c.date, c.start_time`);
      }
      m = path.match(/^\/api\/me\/cleans\/(\d+)\/media\/sign$/);
      if (m && method === "POST") {
        if (!(await ownClean(m[1], me))) return bad("Not your clean", 404);
        const ext = MEDIA_TYPES[body.content_type];
        if (!ext) return bad("Unsupported file type. Use JPG, PNG, HEIC photos or MP4/MOV video.");
        if (!["before", "after", "other"].includes(body.kind)) return bad("Bad kind");
        const [{ n }] = await sql`SELECT count(*)::int AS n FROM coastal.clean_media WHERE clean_id = ${m[1]}`;
        if (n >= 80) return bad("Too many files on this clean");
        const filePath = `${m[1]}/${crypto.randomUUID()}.${ext}`;
        const { data, error } = await supa.storage.from(BUCKET).createSignedUploadUrl(filePath);
        if (error || !data) { console.error(error); return bad("Could not start upload", 500); }
        return json({ path: filePath, signed_url: data.signedUrl });
      }
      m = path.match(/^\/api\/me\/cleans\/(\d+)\/media$/);
      if (m && method === "POST") {
        if (!(await ownClean(m[1], me))) return bad("Not your clean", 404);
        if (!MEDIA_PATH_RE.test(body.path || "") || !String(body.path).startsWith(m[1] + "/")) return bad("Bad file path");
        if (!MEDIA_TYPES[body.content_type] || !["before", "after", "other"].includes(body.kind)) return bad("Bad file info");
        const { data: sd, error: se } = await supa.storage.from(BUCKET).createSignedUrl(body.path, 60);
        if (se || !sd) return bad("That file did not finish uploading. Please try again.");
        const [r] = await sql`INSERT INTO coastal.clean_media (clean_id, kind, path, content_type, size_bytes, caption, uploaded_by)
          VALUES (${m[1]}, ${body.kind}, ${body.path}, ${body.content_type}, ${Number(body.size) || null}, ${String(body.caption ?? "").slice(0, 200)}, ${me}) RETURNING id`;
        return json({ id: Number(r.id) });
      }
      if (m && method === "GET") {
        if (!(await ownClean(m[1], me))) return bad("Not your clean", 404);
        return json(await mediaFor(Number(m[1])));
      }
      m = path.match(/^\/api\/me\/media\/(\d+)$/);
      if (m && method === "DELETE") {
        const [row] = await sql`SELECT mm.id, mm.path FROM coastal.clean_media mm JOIN coastal.cleans c ON c.id = mm.clean_id WHERE mm.id = ${m[1]} AND c.cleaner_id = ${me}`;
        if (!row) return bad("Not found", 404);
        await supa.storage.from(BUCKET).remove([row.path]);
        await sql`DELETE FROM coastal.clean_media WHERE id = ${m[1]}`;
        return json({ ok: true });
      }
      m = path.match(/^\/api\/me\/cleans\/(\d+)\/messages$/);
      if (m) {
        if (!(await ownClean(m[1], me))) return bad("Not your clean", 404);
        if (method === "GET") return json(await threadFor(m[1], "crew", "cleaner"));
        if (method === "POST") {
          const text = clipText(body.body, 2000);
          if (!text) return bad("Please type a message");
          await sql`INSERT INTO coastal.clean_messages (clean_id, thread, sender, body) VALUES (${m[1]}, 'crew', 'cleaner', ${text})`;
          return json({ ok: true });
        }
      }
      m = path.match(/^\/api\/me\/cleans\/(\d+)\/tasks$/);
      if (m && method === "GET") {
        if (!(await ownClean(m[1], me))) return bad("Not your clean", 404);
        return json(await ensureTasks(m[1]));
      }
      m = path.match(/^\/api\/me\/tasks\/(\d+)$/);
      if (m && method === "POST") {
        const r = await sql`UPDATE coastal.clean_tasks t SET done = ${!!body.done}, done_at = ${body.done ? new Date() : null}
          FROM coastal.cleans c WHERE t.id = ${m[1]} AND c.id = t.clean_id AND c.cleaner_id = ${me} AND c.status IN ('assigned','confirmed','done') RETURNING t.id`;
        return r.length ? json({ ok: true }) : bad("Not found", 404);
      }
      m = path.match(/^\/api\/me\/cleans\/(\d+)\/(clock-in|finish|cant-make-it)$/);
      if (m && method === "POST") {
        const [c] = await sql`SELECT id, status, clock_in FROM coastal.cleans WHERE id = ${m[1]} AND cleaner_id = ${me} AND status IN ('assigned','confirmed','done')`;
        if (!c) return bad("Not your clean", 404);
        if (m[2] === "clock-in") {
          if (c.status === "done") return bad("This clean is already finished");
          await sql`UPDATE coastal.cleans SET clock_in = coalesce(clock_in, now()), status = 'confirmed' WHERE id = ${c.id}`;
          return json({ ok: true });
        }
        if (m[2] === "finish") {
          if (c.status === "done") return json({ ok: true });
          const tasks = await ensureTasks(c.id);
          const left = tasks.filter((t: any) => !t.done).length;
          if (left) return bad(`Finish the checklist first (${left} task${left === 1 ? "" : "s"} left)`, 409);
          const kinds = await sql`SELECT DISTINCT kind FROM coastal.clean_media WHERE clean_id = ${c.id}`;
          const have = new Set(kinds.map((k: any) => k.kind));
          if (!have.has("before") || !have.has("after")) return bad("Add at least one BEFORE and one AFTER photo or video first (📷 Photos & video)", 409);
          await sql`UPDATE coastal.cleans SET clock_in = coalesce(clock_in, now()), clock_out = now(), status = 'done' WHERE id = ${c.id}`;
          return json({ ok: true });
        }
        // cant-make-it
        const reason = clipText(body.reason, 300);
        if (!reason) return bad("Please tell Nicole why");
        if (c.clock_in || c.status === "done") return bad("You already started this clean. Message Nicole instead.", 409);
        const [who] = await sql`SELECT name FROM coastal.cleaners WHERE id = ${me}`;
        await sql`INSERT INTO coastal.clean_messages (clean_id, thread, sender, body) VALUES (${c.id}, 'crew', 'cleaner', ${"Can't make this clean: " + reason})`;
        await sql`UPDATE coastal.cleans SET cleaner_id = NULL, status = 'open', release_note = ${who.name + ": " + reason} WHERE id = ${c.id}`;
        return json({ ok: true });
      }
      if (path === "/api/me/supplies" && method === "POST") {
        const item = clipText(body.item, 200);
        if (!item) return bad("What do you need?");
        let cid: number | null = null;
        if (body.clean_id) { if (!(await ownClean(String(body.clean_id), me))) return bad("Not your clean", 404); cid = Number(body.clean_id); }
        await sql`INSERT INTO coastal.supply_requests (clean_id, cleaner_id, item) VALUES (${cid}, ${me}, ${item})`;
        return json({ ok: true });
      }
      if (path === "/api/me/supplies" && method === "GET")
        return json(await sql`SELECT s.id, s.item, s.status, s.created_at, c.client FROM coastal.supply_requests s LEFT JOIN coastal.cleans c ON c.id = s.clean_id
          WHERE s.cleaner_id = ${me} ORDER BY s.id DESC LIMIT 15`);
      m = path.match(/^\/api\/me\/cleans\/(\d+)\/confirm$/);
      if (m && method === "POST") {
        const r = await sql`UPDATE coastal.cleans SET status = 'confirmed' WHERE id = ${m[1]} AND cleaner_id = ${me} AND status = 'assigned' RETURNING id`;
        return r.length ? json({ ok: true }) : bad("Nothing to confirm", 404);
      }
      return bad("Not found", 404);
    }

    // ---- admin ----
    if (path.startsWith("/api/admin/")) {
      if (user.role !== "admin") return bad("Not allowed", 403);

      // ---- alerts (late / unfilled) ----
      if (path === "/api/admin/alerts" && method === "GET") {
        const rows = await sql`SELECT ${CLEAN_COLS}, cl.name AS cleaner_name, cl.phone AS cleaner_phone,
          CASE WHEN c.cleaner_id IS NULL THEN 'unfilled' ELSE 'late' END AS kind
          FROM coastal.cleans c LEFT JOIN coastal.cleaners cl ON cl.id = c.cleaner_id
          WHERE (c.cleaner_id IS NOT NULL AND c.status IN ('assigned','confirmed') AND c.clock_in IS NULL
                 AND c.date >= ${today()}::date - 3 AND (c.date < ${today()}::date OR (c.date = ${today()}::date AND c.start_time + interval '15 minutes' < (now() AT TIME ZONE 'America/New_York')::time)))
             OR (c.cleaner_id IS NULL AND c.status = 'open' AND c.date BETWEEN ${today()}::date AND ${today()}::date + 2)
          ORDER BY c.date, c.start_time`;
        return json(rows);
      }
      // ---- history / search ----
      if (path === "/api/admin/history" && method === "GET") {
        const q = clipText(url.searchParams.get("q") ?? "", 80);
        const like = "%" + q.replace(/[%_\\]/g, "\\$&") + "%";
        return json(await sql`SELECT ${CLEAN_COLS}, cl.name AS cleaner_name, cl.phone AS cleaner_phone,
          (SELECT count(*) FROM coastal.clean_media mm WHERE mm.clean_id = c.id)::int AS media_count,
          (SELECT coalesce(sum(fee_cents),0) FROM coastal.clean_messages fm WHERE fm.clean_id = c.id AND fm.fee_status = 'approved')::int AS fees_approved_cents,
          (SELECT count(*) FROM coastal.clean_messages fm WHERE fm.clean_id = c.id AND fm.fee_status = 'pending')::int AS fees_pending
          FROM coastal.cleans c LEFT JOIN coastal.cleaners cl ON cl.id = c.cleaner_id
          WHERE c.status != 'requested' AND (${q === ""} OR c.client ILIKE ${like} OR c.address ILIKE ${like} OR c.contact_name ILIKE ${like} OR cl.name ILIKE ${like}
            OR EXISTS (SELECT 1 FROM coastal.properties p WHERE p.id = c.property_id AND p.name ILIKE ${like}))
          ORDER BY c.date DESC, c.start_time DESC LIMIT 60`);
      }

      // ---- properties ----
      if (path === "/api/admin/properties" && method === "GET")
        return json(await sql`SELECT id, name, address, owner_name, owner_phone, owner_email, access_info, checklist, default_type, default_hours::float AS default_hours, active FROM coastal.properties ORDER BY active DESC, name`);
      const propFields = (b: any) => ({ name: clipText(b.name, 120), address: clipText(b.address, 200), owner_name: clipText(b.owner_name, 100) || null,
        owner_phone: clipText(b.owner_phone, 30) || null, owner_email: clipText(b.owner_email, 120) || null, access_info: clipText(b.access_info, 1500),
        checklist: clipText(b.checklist, 4000), default_type: clipText(b.default_type, 40) || "Airbnb turnover",
        default_hours: Number(b.default_hours) > 0 && Number(b.default_hours) <= 16 ? Number(b.default_hours) : 2 });
      if (path === "/api/admin/properties" && method === "POST") {
        const f = propFields(body); if (!f.name) return bad("Property name required");
        const [r] = await sql`INSERT INTO coastal.properties (name, address, owner_name, owner_phone, owner_email, access_info, checklist, default_type, default_hours)
          VALUES (${f.name}, ${f.address}, ${f.owner_name}, ${f.owner_phone}, ${f.owner_email}, ${f.access_info}, ${f.checklist}, ${f.default_type}, ${f.default_hours}) RETURNING id`;
        return json({ id: Number(r.id) });
      }
      let m = path.match(/^\/api\/admin\/properties\/(\d+)$/);
      if (m && method === "PATCH") {
        const [cur] = await sql`SELECT * FROM coastal.properties WHERE id = ${m[1]}`;
        if (!cur) return bad("Not found", 404);
        if (Object.keys(body).length === 1 && "active" in body) { await sql`UPDATE coastal.properties SET active = ${!!body.active} WHERE id = ${m[1]}`; return json({ ok: true }); }
        const f = propFields(body); if (!f.name) return bad("Property name required");
        await sql`UPDATE coastal.properties SET name = ${f.name}, address = ${f.address}, owner_name = ${f.owner_name}, owner_phone = ${f.owner_phone}, owner_email = ${f.owner_email},
          access_info = ${f.access_info}, checklist = ${f.checklist}, default_type = ${f.default_type}, default_hours = ${f.default_hours} WHERE id = ${m[1]}`;
        return json({ ok: true });
      }

      // ---- recurring + repeat ----
      if (path === "/api/admin/recurring/generate" && method === "POST") { await generateRecurring(); return json({ ok: true }); }
      if (path === "/api/admin/recurring" && method === "GET")
        return json(await sql`SELECT r.id, r.client, r.address, r.type, to_char(r.start_time,'HH24:MI') AS start_time, r.every_weeks, r.start_date::text AS start_date, r.end_date::text AS end_date, r.active
          FROM coastal.recurring_rules r ORDER BY r.active DESC, r.client`);
      if (path === "/api/admin/recurring" && method === "POST") {
        const [c] = await sql`SELECT * FROM coastal.cleans WHERE id = ${Number(body.clean_id) || 0}`;
        if (!c) return bad("Clean not found", 404);
        const every = Math.min(8, Math.max(1, Number(body.every_weeks) || 1));
        const [r] = await sql`INSERT INTO coastal.recurring_rules (property_id, client, address, type, start_time, duration_hours, notes, contact_name, contact_phone, contact_email, start_date, every_weeks)
          VALUES (${c.property_id}, ${c.client}, ${c.address}, ${c.type}, ${c.start_time}, ${c.duration_hours}, ${c.notes ?? ""}, ${c.contact_name}, ${c.contact_phone}, ${c.contact_email}, ${c.date}, ${every}) RETURNING id`;
        await sql`UPDATE coastal.cleans SET rule_id = ${r.id} WHERE id = ${c.id} AND rule_id IS NULL`;
        await generateRecurring();
        return json({ id: Number(r.id) });
      }
      m = path.match(/^\/api\/admin\/recurring\/(\d+)$/);
      if (m && (method === "PATCH" || method === "DELETE")) {
        const stop = method === "DELETE" || body.active === false;
        if (stop) {
          await sql`UPDATE coastal.cleans SET status = 'cancelled' WHERE rule_id = ${m[1]} AND status = 'open' AND date >= ${today()}`;
          if (method === "DELETE") await sql`DELETE FROM coastal.recurring_rules WHERE id = ${m[1]}`;
          else await sql`UPDATE coastal.recurring_rules SET active = false WHERE id = ${m[1]}`;
        } else { await sql`UPDATE coastal.recurring_rules SET active = true WHERE id = ${m[1]}`; await generateRecurring(); }
        return json({ ok: true });
      }
      m = path.match(/^\/api\/admin\/cleans\/(\d+)\/repeat$/);
      if (m && method === "POST") {
        if (!DATE_RE.test(body.date || "")) return bad("Pick a date");
        const [r] = await sql`INSERT INTO coastal.cleans (date, start_time, duration_hours, client, address, type, notes, contact_name, contact_phone, contact_email, property_id)
          SELECT ${body.date}, start_time, duration_hours, client, address, type, notes, contact_name, contact_phone, contact_email, property_id FROM coastal.cleans WHERE id = ${m[1]} RETURNING id`;
        return r ? json({ id: Number(r.id) }) : bad("Not found", 404);
      }

      // ---- checklist (admin view/edit per clean) ----
      m = path.match(/^\/api\/admin\/cleans\/(\d+)\/tasks$/);
      if (m && method === "GET") return json(await ensureTasks(m[1]));
      if (m && method === "POST") {
        const label = clipText(body.label, 200); if (!label) return bad("Task text required");
        await ensureTasks(m[1]);
        await sql`INSERT INTO coastal.clean_tasks (clean_id, label, sort) VALUES (${m[1]}, ${label}, (SELECT coalesce(max(sort),0)+1 FROM coastal.clean_tasks WHERE clean_id = ${m[1]}))`;
        return json({ ok: true });
      }
      m = path.match(/^\/api\/admin\/tasks\/(\d+)$/);
      if (m && method === "DELETE") { await sql`DELETE FROM coastal.clean_tasks WHERE id = ${m[1]}`; return json({ ok: true }); }

      // ---- supplies ----
      if (path === "/api/admin/supplies" && method === "GET")
        return json(await sql`SELECT s.id, s.item, s.status, s.created_at, c.client, c.date::text AS date, cl.name AS cleaner_name FROM coastal.supply_requests s
          LEFT JOIN coastal.cleans c ON c.id = s.clean_id LEFT JOIN coastal.cleaners cl ON cl.id = s.cleaner_id
          WHERE s.status != 'done' OR s.created_at > now() - interval '14 days' ORDER BY (s.status = 'done'), s.id DESC LIMIT 100`);
      m = path.match(/^\/api\/admin\/supplies\/(\d+)$/);
      if (m && method === "PATCH") {
        if (!["open", "ordered", "done"].includes(body.status)) return bad("Bad status");
        await sql`UPDATE coastal.supply_requests SET status = ${body.status} WHERE id = ${m[1]}`; return json({ ok: true });
      }

      if (path === "/api/admin/cleaners" && method === "GET")
        return json(await sql`SELECT id, name, phone, pin, active FROM coastal.cleaners ORDER BY active DESC, name`);
      if (path === "/api/admin/cleaners" && method === "POST") {
        if (!body.name || !/^\d{4,8}$/.test(body.pin || "")) return bad("Name and a 4-8 digit PIN required");
        const [r] = await sql`INSERT INTO coastal.cleaners (name, phone, pin) VALUES (${String(body.name).trim()}, ${body.phone ?? ""}, ${body.pin}) RETURNING id`;
        return json({ id: Number(r.id) });
      }
      m = path.match(/^\/api\/admin\/cleaners\/(\d+)$/);
      if (m && method === "PATCH") {
        const [c] = await sql`SELECT * FROM coastal.cleaners WHERE id = ${m[1]}`;
        if (!c) return bad("Not found", 404);
        const n = { ...c, ...body };
        if (!/^\d{4,8}$/.test(n.pin)) return bad("PIN must be 4-8 digits");
        await sql`UPDATE coastal.cleaners SET name = ${n.name}, phone = ${n.phone ?? ""}, pin = ${n.pin}, active = ${!!n.active} WHERE id = ${m[1]}`;
        return json({ ok: true });
      }

      if (path === "/api/admin/cleans" && method === "POST") {
        const b = { start_time: "10:00", duration_hours: 2, type: "Airbnb turnover", ...body };
        const err = validateClean(b);
        if (err) return bad(err);
        const [r] = await sql`INSERT INTO coastal.cleans (date, start_time, duration_hours, client, address, type, notes, contact_name, contact_phone, contact_email, property_id)
          VALUES (${b.date}, ${b.start_time}, ${b.duration_hours}, ${b.client}, ${b.address ?? ""}, ${b.type}, ${b.notes ?? ""}, ${b.contact_name ?? null}, ${b.contact_phone ?? null}, ${b.contact_email ?? null}, ${b.property_id ? Number(b.property_id) : null}) RETURNING id`;
        return json({ id: Number(r.id) });
      }
      m = path.match(/^\/api\/admin\/cleans\/(\d+)$/);
      if (m && method === "PATCH") {
        const [c] = await sql`SELECT ${CLEAN_COLS} FROM coastal.cleans c WHERE c.id = ${m[1]}`;
        if (!c) return bad("Not found", 404);
        const n = { ...c, ...body, id: c.id, cleaner_id: c.cleaner_id };
        const err = validateClean(n);
        if (err) return bad(err);
        if (!["requested", "declined", "open", "assigned", "confirmed", "done", "cancelled"].includes(n.status)) return bad("Bad status");
        await sql`UPDATE coastal.cleans SET date = ${n.date}, start_time = ${n.start_time}, duration_hours = ${n.duration_hours},
          client = ${n.client}, address = ${n.address ?? ""}, type = ${n.type}, notes = ${n.notes ?? ""}, status = ${n.status},
          contact_name = ${n.contact_name ?? null}, contact_phone = ${n.contact_phone ?? null}, contact_email = ${n.contact_email ?? null}, property_id = ${n.property_id ? Number(n.property_id) : null} WHERE id = ${m[1]}`;
        return json({ ok: true });
      }
      if (m && method === "DELETE") { await sql`DELETE FROM coastal.cleans WHERE id = ${m[1]}`; return json({ ok: true }); }

      m = path.match(/^\/api\/admin\/cleans\/(\d+)\/media$/);
      if (m && method === "GET") {
        const [c] = await sql`SELECT report_token, report_published, report_note FROM coastal.cleans WHERE id = ${m[1]}`;
        if (!c) return bad("Not found", 404);
        return json({ media: await mediaFor(Number(m[1])), report: { token: c.report_token, published: c.report_published, note: c.report_note ?? "" } });
      }
      m = path.match(/^\/api\/admin\/cleans\/(\d+)\/report$/);
      if (m && method === "POST") {
        const note = String(body.note ?? "").slice(0, 2000);
        const [c] = await sql`UPDATE coastal.cleans SET report_published = ${!!body.publish}, report_note = ${note} WHERE id = ${m[1]} RETURNING report_token, report_published`;
        if (!c) return bad("Not found", 404);
        return json({ token: c.report_token, published: c.report_published });
      }
      m = path.match(/^\/api\/admin\/cleans\/(\d+)\/messages$/);
      if (m) {
        const thread = method === "GET" ? (url.searchParams.get("thread") ?? "") : String(body.thread ?? "");
        if (!["crew", "client"].includes(thread)) return bad("Bad thread");
        const [exists] = await sql`SELECT 1 FROM coastal.cleans WHERE id = ${m[1]}`;
        if (!exists) return bad("Not found", 404);
        if (method === "GET") return json(await threadFor(m[1], thread, "admin"));
        if (method === "POST") {
          const text = clipText(body.body, 2000);
          if (!text) return bad("Please type a message");
          let feeCents: number | null = null;
          if (body.fee_dollars != null && body.fee_dollars !== "") {
            if (thread !== "client") return bad("Fees can only be requested from the owner");
            feeCents = Math.round(Number(body.fee_dollars) * 100);
            if (!Number.isFinite(feeCents) || feeCents < 1 || feeCents > 1000000) return bad("Enter a fee between $0.01 and $10,000");
          }
          await sql`INSERT INTO coastal.clean_messages (clean_id, thread, sender, body, fee_cents, fee_status)
            VALUES (${m[1]}, ${thread}, 'admin', ${text}, ${feeCents}, ${feeCents ? "pending" : null})`;
          return json({ ok: true });
        }
      }
      m = path.match(/^\/api\/admin\/media\/(\d+)$/);
      if (m && method === "DELETE") {
        const [row] = await sql`SELECT path FROM coastal.clean_media WHERE id = ${m[1]}`;
        if (!row) return bad("Not found", 404);
        await supa.storage.from(BUCKET).remove([row.path]);
        await sql`DELETE FROM coastal.clean_media WHERE id = ${m[1]}`;
        return json({ ok: true });
      }

      if (path === "/api/admin/requests" && method === "GET")
        return json(await sql`SELECT ${CLEAN_COLS} FROM coastal.cleans c WHERE c.status = 'requested' ORDER BY c.date, c.created_at`);

      if (path === "/api/admin/board" && method === "GET") {
        const from = url.searchParams.get("from") ?? "", to = url.searchParams.get("to") ?? "";
        if (!DATE_RE.test(from) || !DATE_RE.test(to)) return bad("from/to required (YYYY-MM-DD)");
        const cleans = await sql`SELECT ${CLEAN_COLS}, cl.name AS cleaner_name, cl.phone AS cleaner_phone,
          (SELECT count(*) FROM coastal.clean_messages mm WHERE mm.clean_id = c.id AND mm.thread = 'crew' AND mm.sender = 'cleaner' AND NOT mm.seen)::int AS unread_crew,
          (SELECT count(*) FROM coastal.clean_messages mm WHERE mm.clean_id = c.id AND mm.thread = 'client' AND mm.sender = 'client' AND NOT mm.seen)::int AS unread_client,
          (SELECT count(*) FROM coastal.clean_tasks t WHERE t.clean_id = c.id)::int AS tasks_total,
          (SELECT count(*) FROM coastal.clean_tasks t WHERE t.clean_id = c.id AND t.done)::int AS tasks_done
          FROM coastal.cleans c LEFT JOIN coastal.cleaners cl ON cl.id = c.cleaner_id
          WHERE c.date BETWEEN ${from} AND ${to} AND c.status NOT IN ('cancelled','requested','declined') ORDER BY c.date, c.start_time`;
        const availability = await sql`SELECT ${AVAIL_COLS}, cl.name FROM coastal.availability a JOIN coastal.cleaners cl ON cl.id = a.cleaner_id
          WHERE a.date BETWEEN ${from} AND ${to} AND cl.active ORDER BY cl.name`;
        return json({ cleans, availability });
      }

      m = path.match(/^\/api\/admin\/cleans\/(\d+)\/(candidates|assign|unassign)$/);
      if (m) {
        const [c] = await sql`SELECT ${CLEAN_COLS} FROM coastal.cleans c WHERE c.id = ${m[1]}`;
        if (!c) return bad("Not found", 404);
        if (m[2] === "candidates" && method === "GET") return json(await candidatesFor(c));
        if (m[2] === "unassign" && method === "POST") {
          await sql`UPDATE coastal.cleans SET cleaner_id = NULL, status = 'open' WHERE id = ${c.id}`;
          return json({ ok: true });
        }
        if (m[2] === "assign" && method === "POST") {
          const [cleaner] = await sql`SELECT * FROM coastal.cleaners WHERE id = ${Number(body.cleaner_id) || 0} AND active`;
          if (!cleaner) return bad("Cleaner not found");
          const cand = (await candidatesFor(c)).find((x: any) => x.cleaner_id === Number(cleaner.id));
          const problems: string[] = [];
          if (!cand) problems.push(`${cleaner.name} did not post that day`);
          else {
            if (!cand.fits_window) problems.push(`${cleaner.name}'s hours that day are ${cand.window}`);
            if (cand.conflict) problems.push(`overlaps ${cand.conflict}`);
          }
          if (problems.length && !body.force) return bad(problems.join("; "), 409, { needs_force: true });
          await sql`UPDATE coastal.cleans SET cleaner_id = ${cleaner.id}, status = 'assigned', release_note = NULL WHERE id = ${c.id}`;
          return json({ ok: true, warnings: problems });
        }
      }
      return bad("Not found", 404);
    }
    return bad("Not found", 404);
  } catch (e) {
    console.error(e);
    return bad("Server error", 500);
  }
});
