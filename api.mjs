// Northern Spirit website server.
// Stores the site content, uploaded photos and the owner access code in Netlify Blobs.
//
//   GET  /api/content          public: everything the page shows
//   POST /api/login            { code }               -> 200 or 401
//   POST /api/save             { code, content }      -> replaces all content
//   POST /api/upload           body = image, header x-access-code -> { url }
//   GET  /api/img/<key>        public: an uploaded photo
//   POST /api/code             { code, newCode }      -> changes the access code
//
// The first access code comes from the INITIAL_ACCESS_CODE environment variable.
// Once the owner changes it, only a salted hash of the new code is stored.

import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

const MAX_CONTENT = 1_000_000;          // bytes of JSON
const MAX_IMAGE = 8 * 1024 * 1024;      // 8 MB per photo
const IMAGE_TYPES = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif" };
const MAX_FAILS = 10, FAIL_WINDOW = 15 * 60 * 1000;

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

const stores = () => ({
  content: getStore({ name: "site-content", consistency: "strong" }),
  auth: getStore({ name: "site-auth", consistency: "strong" }),
  images: getStore({ name: "site-images" })
});

const sha = s => crypto.createHash("sha256").update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const scrypt = (code, salt) => crypto.scryptSync(String(code), salt, 32).toString("hex");

function clientIp(req, context){
  return (context && context.ip) || req.headers.get("x-nf-client-connection-ip") || req.headers.get("x-forwarded-for") || "unknown";
}

async function tooManyFails(auth, ip){
  const rec = await auth.get("fails:" + ip, { type: "json" });
  return !!(rec && rec.n >= MAX_FAILS && Date.now() - rec.t < FAIL_WINDOW);
}
async function noteFail(auth, ip){
  const key = "fails:" + ip, rec = await auth.get(key, { type: "json" });
  const fresh = !rec || Date.now() - rec.t >= FAIL_WINDOW;
  await auth.setJSON(key, { n: fresh ? 1 : rec.n + 1, t: fresh ? Date.now() : rec.t });
}

async function codeMatches(auth, code){
  if (typeof code !== "string" || !code) return false;
  const rec = await auth.get("code", { type: "json" });
  if (rec && rec.hash && rec.salt) return same(scrypt(code, rec.salt), rec.hash);
  const initial = process.env.INITIAL_ACCESS_CODE;
  return !!initial && same(code, initial);
}

// Checks the code, with a limit on wrong guesses per visitor. Returns a Response on failure.
async function requireCode(req, context, auth, code){
  const ip = clientIp(req, context);
  if (await tooManyFails(auth, ip)) return json({ error: "Too many wrong codes. Try again later." }, 429);
  if (!(await codeMatches(auth, code))){ await noteFail(auth, ip); return json({ error: "Wrong access code." }, 401); }
  return null;
}

async function readJson(req){
  const text = await req.text();
  if (text.length > MAX_CONTENT + 10_000) throw Object.assign(new Error("Too large."), { status: 413 });
  try { return JSON.parse(text || "{}"); } catch { throw Object.assign(new Error("Not valid JSON."), { status: 400 }); }
}

export default async (req, context) => {
  const url = new URL(req.url);
  const route = url.pathname.replace(/^\/api\/?/, "").replace(/\/+$/, "");
  const { content, auth, images } = stores();

  try {
    if (req.method === "GET" && route === "content"){
      const data = await content.get("main", { type: "json" });
      return json({ content: data || null });
    }

    if (req.method === "GET" && route.startsWith("img/")){
      const key = route.slice(4);
      if (!/^[a-z0-9-]+\.(jpg|png|webp|gif)$/.test(key)) return json({ error: "Not found." }, 404);
      const found = await images.getWithMetadata(key, { type: "arrayBuffer" });
      if (!found) return json({ error: "Not found." }, 404);
      return new Response(found.data, { headers: {
        "content-type": (found.metadata && found.metadata.type) || "application/octet-stream",
        "cache-control": "public, max-age=31536000, immutable"
      } });
    }

    if (req.method !== "POST") return json({ error: "Not found." }, 404);

    if (route === "upload"){
      const fail = await requireCode(req, context, auth, req.headers.get("x-access-code") || "");
      if (fail) return fail;
      const type = (req.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
      if (!IMAGE_TYPES[type]) return json({ error: "Upload a JPG, PNG, WebP or GIF photo." }, 415);
      const buf = await req.arrayBuffer();
      if (!buf.byteLength) return json({ error: "The file is empty." }, 400);
      if (buf.byteLength > MAX_IMAGE) return json({ error: "Photos must be 8 MB or smaller." }, 413);
      const key = `${crypto.randomUUID()}.${IMAGE_TYPES[type]}`;
      await images.set(key, buf, { metadata: { type } });
      return json({ url: "/api/img/" + key });
    }

    const body = await readJson(req);

    if (route === "login"){
      const fail = await requireCode(req, context, auth, body.code);
      return fail || json({ ok: true });
    }

    if (route === "save"){
      const fail = await requireCode(req, context, auth, body.code);
      if (fail) return fail;
      const c = body.content;
      if (!c || typeof c !== "object" || Array.isArray(c)) return json({ error: "Nothing to save." }, 400);
      const clean = {};
      for (const k of ["site", "classes", "timetable", "coaches", "kit", "faqs"]){
        if (k === "site"){ if (c.site && typeof c.site === "object" && !Array.isArray(c.site)) clean.site = c.site; }
        else if (Array.isArray(c[k])) clean[k] = c[k].filter(r => r && typeof r === "object");
      }
      if (JSON.stringify(clean).length > MAX_CONTENT) return json({ error: "Too much content to save." }, 413);
      await content.setJSON("main", clean);
      return json({ ok: true });
    }

    if (route === "code"){
      const fail = await requireCode(req, context, auth, body.code);
      if (fail) return fail;
      const next = typeof body.newCode === "string" ? body.newCode.trim() : "";
      if (next.length < 6) return json({ error: "Use at least 6 characters." }, 400);
      const salt = crypto.randomBytes(16).toString("hex");
      await auth.setJSON("code", { salt, hash: scrypt(next, salt), changed: new Date().toISOString() });
      return json({ ok: true });
    }

    return json({ error: "Not found." }, 404);
  } catch (e) {
    return json({ error: e.status ? e.message : "Something went wrong." }, e.status || 500);
  }
};
