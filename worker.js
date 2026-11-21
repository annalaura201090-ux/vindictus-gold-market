const COOKIE_NAME = "__Host-vgm_admin";
const SESSION_SECONDS = 60 * 60 * 8;
const PBKDF2_ITERATIONS = 310000;
const ALLOWED_SERVERS = new Set(["NA", "EU"]);
const ALLOWED_STATUSES = new Set(["pending", "paid", "processing", "completed", "cancelled"]);

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers }
  });
}
function fail(message, status = 400) { return json({ ok: false, error: message }, status); }
function nowIso() { return new Date().toISOString(); }
function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}
function toBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return toBase64Url(new Uint8Array(digest));
}
async function passwordHash(password) {
  const salt = randomBytes(16);
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS }, material, 256);
  return `pbkdf2-sha256$${PBKDF2_ITERATIONS}$${toBase64Url(salt)}$${toBase64Url(new Uint8Array(bits))}`;
}
async function verifyPassword(password, stored) {
  try {
    const [scheme, iterationText, saltText, expectedText] = stored.split("$");
    if (scheme !== "pbkdf2-sha256") return false;
    const iterations = Number(iterationText);
    if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 1000000) return false;
    const salt = fromBase64Url(saltText);
    const expected = fromBase64Url(expectedText);
    const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, material, expected.length * 8));
    if (bits.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < bits.length; i++) diff |= bits[i] ^ expected[i];
    return diff === 0;
  } catch { return false; }
}
function cookieValue(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return null;
}
function cookieHeader(value, maxAge) {
  return `${COOKIE_NAME}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}
function clearCookieHeader() { return `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`; }
async function readJson(request, maxBytes = 20000) {
  const length = Number(request.headers.get("content-length") || 0);
  if (length > maxBytes) throw new Error("Ukuran data terlalu besar.");
  const text = await request.text();
  if (new TextEncoder().encode(text).length > maxBytes) throw new Error("Ukuran data terlalu besar.");
  return JSON.parse(text || "{}");
}
function validServer(server) { return typeof server === "string" && ALLOWED_SERVERS.has(server.toUpperCase()); }
function normalizeServer(server) { return String(server || "").toUpperCase(); }
function safeText(value, max = 120) { return typeof value === "string" ? value.trim().slice(0, max) : ""; }
async function hasAdmin(db) {
  const result = await db.prepare("SELECT COUNT(*) AS total FROM admin_users").first();
  return Number(result?.total || 0) > 0;
}
async function createSession(db, adminId) {
  const token = toBase64Url(randomBytes(32));
  const tokenHash = await sha256(token);
  const expires = new Date(Date.now() + SESSION_SECONDS * 1000).toISOString();
  await db.prepare("INSERT INTO admin_sessions (session_token_hash, admin_id, expires_at, created_at) VALUES (?, ?, ?, ?)")
    .bind(tokenHash, adminId, expires, nowIso()).run();
  return token;
}
async function authenticatedAdmin(request, env) {
  const token = cookieValue(request, COOKIE_NAME);
  if (!token || token.length > 200) return null;
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(
    "SELECT admin_users.id, admin_users.username FROM admin_sessions JOIN admin_users ON admin_users.id = admin_sessions.admin_id WHERE admin_sessions.session_token_hash = ? AND admin_sessions.expires_at > ? LIMIT 1"
  ).bind(tokenHash, nowIso()).first();
  return row || null;
}
function isSameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  try { return new URL(origin).host === new URL(request.url).host; } catch { return false; }
}
async function requireAdmin(request, env) {
  if (!isSameOrigin(request)) return { response: fail("Permintaan lintas situs ditolak.", 403) };
  const admin = await authenticatedAdmin(request, env);
  if (!admin) return { response: fail("Sesi admin berakhir. Silakan login kembali.", 401) };
  return { admin };
}

async function handleApi(request, env, url) {
  const path = url.pathname;
  const method = request.method;

  // Endpoint pemeriksaan awal dipertahankan.
  if (path === "/api/health" && method === "GET") {
    try {
      const result = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all();
      return json({ status: "ok", database: "connected", tables: result.results });
    } catch {
      return json({ status: "error", message: "Database belum terhubung" }, 500);
    }
  }

  if (path === "/api/admin/setup-status" && method === "GET") {
    try { return json({ setupRequired: !(await hasAdmin(env.DB)) }); }
    catch { return fail("Tidak dapat memeriksa status admin.", 500); }
  }

  if (path === "/api/admin/setup" && method === "POST") {
    if (!isSameOrigin(request)) return fail("Permintaan lintas situs ditolak.", 403);
    try {
      if (await hasAdmin(env.DB)) return fail("Akun admin pertama sudah dibuat. Pendaftaran ditutup.", 409);
      if (!env.ADMIN_SETUP_KEY) return fail("ADMIN_SETUP_KEY tidak tersedia. Tambahkan Secret di Cloudflare Production.", 503);
      const body = await readJson(request, 10000);
      const setupKey = safeText(body.setupKey, 500);
      const username = safeText(body.username, 40);
      const password = typeof body.password === "string" ? body.password : "";
      if (!setupKey || setupKey !== env.ADMIN_SETUP_KEY) return fail("ADMIN_SETUP_KEY tidak cocok.", 403);
      if (!/^[a-zA-Z0-9_.-]{3,40}$/.test(username)) return fail("Username harus 3–40 karakter (huruf, angka, titik, garis, underscore). ");
      if (password.length < 12 || password.length > 200) return fail("Password wajib 12–200 karakter.");
      const hash = await passwordHash(password);
      // Conditional insert menjaga agar hanya satu pendaftaran pertama yang berhasil.
      const inserted = await env.DB.prepare(
        "INSERT INTO admin_users (username, password_hash, created_at) SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM admin_users)"
      ).bind(username, hash, nowIso()).run();
      if (!inserted.meta?.changes) return fail("Akun admin pertama sudah dibuat. Pendaftaran ditutup.", 409);
      const admin = await env.DB.prepare("SELECT id, username FROM admin_users WHERE username = ? LIMIT 1").bind(username).first();
      const token = await createSession(env.DB, admin.id);
      return json({ ok: true, username: admin.username }, 201, { "set-cookie": cookieHeader(token, SESSION_SECONDS) });
    } catch (error) { return fail(error.message || "Pembuatan admin gagal.", 400); }
  }

  if (path === "/api/admin/login" && method === "POST") {
    if (!isSameOrigin(request)) return fail("Permintaan lintas situs ditolak.", 403);
    try {
      const body = await readJson(request, 10000);
      const username = safeText(body.username, 40);
      const password = typeof body.password === "string" ? body.password : "";
      const admin = await env.DB.prepare("SELECT id, username, password_hash FROM admin_users WHERE username = ? LIMIT 1").bind(username).first();
      const valid = admin ? await verifyPassword(password, admin.password_hash) : false;
      if (!valid) return fail("Username atau password salah.", 401);
      const token = await createSession(env.DB, admin.id);
      return json({ ok: true, username: admin.username }, 200, { "set-cookie": cookieHeader(token, SESSION_SECONDS) });
    } catch { return fail("Login gagal diproses.", 400); }
  }

  if (path === "/api/admin/logout" && method === "POST") {
    if (!isSameOrigin(request)) return fail("Permintaan lintas situs ditolak.", 403);
    const token = cookieValue(request, COOKIE_NAME);
    if (token) await env.DB.prepare("DELETE FROM admin_sessions WHERE session_token_hash = ?").bind(await sha256(token)).run();
    return json({ ok: true }, 200, { "set-cookie": clearCookieHeader() });
  }

  if (!path.startsWith("/api/admin/")) return fail("API tidak ditemukan.", 404);
  const auth = await requireAdmin(request, env);
  if (!auth.admin) return auth.response;

  if (path === "/api/admin/me" && method === "GET") return json({ ok: true, username: auth.admin.username });

  if (path === "/api/admin/dashboard" && method === "GET") {
    const [total, pending, paid, processing, completed, cancelled] = await Promise.all(
      [null, "pending", "paid", "processing", "completed", "cancelled"].map(status =>
        status === null
          ? env.DB.prepare("SELECT COUNT(*) AS n FROM orders").first()
          : env.DB.prepare("SELECT COUNT(*) AS n FROM orders WHERE status = ?").bind(status).first()
      )
    );
    return json({ total: total.n, pending: pending.n, paid: paid.n, processing: processing.n, completed: completed.n, cancelled: cancelled.n });
  }

  if (path === "/api/admin/products" && method === "GET") {
    const rows = await env.DB.prepare("SELECT id, server, package_amount, price_idr, is_active, created_at FROM products ORDER BY server, id").all();
    return json({ products: rows.results || [] });
  }
  if (path === "/api/admin/products" && method === "POST") {
    const body = await readJson(request);
    const server = normalizeServer(body.server);
    const packageAmount = safeText(String(body.package_amount ?? ""), 80);
    const price = Number(body.price_idr);
    const active = body.is_active === false || body.is_active === 0 ? 0 : 1;
    if (!validServer(server) || !packageAmount || !Number.isSafeInteger(price) || price < 0) return fail("Server, paket, atau harga tidak valid.");
    if (body.id !== undefined && body.id !== null && body.id !== "") {
      await env.DB.prepare("UPDATE products SET server = ?, package_amount = ?, price_idr = ?, is_active = ? WHERE id = ?")
        .bind(server, packageAmount, price, active, Number(body.id)).run();
    } else {
      await env.DB.prepare("INSERT INTO products (server, package_amount, price_idr, is_active, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(server, packageAmount, price, active, nowIso()).run();
    }
    return json({ ok: true });
  }
  if (path.startsWith("/api/admin/products/") && method === "DELETE") {
    const id = Number(path.split("/").pop());
    if (!Number.isSafeInteger(id) || id <= 0) return fail("ID paket tidak valid.");
    await env.DB.prepare("UPDATE products SET is_active = 0 WHERE id = ?").bind(id).run();
    return json({ ok: true });
  }

  if (path === "/api/admin/stock" && method === "GET") {
    const rows = await env.DB.prepare("SELECT server, available_gold, updated_at FROM stock ORDER BY server").all();
    return json({ stock: rows.results || [] });
  }
  if (path === "/api/admin/stock" && method === "POST") {
    const body = await readJson(request);
    const server = normalizeServer(body.server);
    const availableGold = Number(body.available_gold);
    if (!validServer(server) || !Number.isSafeInteger(availableGold) || availableGold < 0) return fail("Server atau jumlah stok tidak valid.");
    const existingStock = await env.DB.prepare("SELECT server FROM stock WHERE server = ? LIMIT 1").bind(server).first();
    if (existingStock) {
      await env.DB.prepare("UPDATE stock SET available_gold = ?, updated_at = ? WHERE server = ?")
        .bind(availableGold, nowIso(), server).run();
    } else {
      await env.DB.prepare("INSERT INTO stock (server, available_gold, updated_at) VALUES (?, ?, ?)")
        .bind(server, availableGold, nowIso()).run();
    }
    return json({ ok: true });
  }

  if (path === "/api/admin/orders" && method === "GET") {
    const status = url.searchParams.get("status");
    const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 100), 1), 300);
    let result;
    if (status && ALLOWED_STATUSES.has(status)) {
      result = await env.DB.prepare("SELECT order_code, customer_name, character_name, contact, server, gold_amount, total_price, payment_method, payment_proof_url, status, created_at, updated_at FROM orders WHERE status = ? ORDER BY created_at DESC LIMIT ?").bind(status, limit).all();
    } else {
      result = await env.DB.prepare("SELECT order_code, customer_name, character_name, contact, server, gold_amount, total_price, payment_method, payment_proof_url, status, created_at, updated_at FROM orders ORDER BY created_at DESC LIMIT ?").bind(limit).all();
    }
    return json({ orders: result.results || [] });
  }
  if (path.startsWith("/api/admin/orders/") && path.endsWith("/status") && method === "PATCH") {
    const orderCode = decodeURIComponent(path.split("/")[4] || "");
    const body = await readJson(request);
    const status = safeText(body.status, 20).toLowerCase();
    if (!orderCode || !ALLOWED_STATUSES.has(status)) return fail("Nomor pesanan atau status tidak valid.");
    const result = await env.DB.prepare("UPDATE orders SET status = ?, updated_at = ? WHERE order_code = ?").bind(status, nowIso(), orderCode).run();
    if (!result.meta?.changes) return fail("Pesanan tidak ditemukan.", 404);
    return json({ ok: true });
  }
  return fail("Endpoint admin tidak ditemukan.", 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let response;
    try {
      if (url.pathname.startsWith("/api/")) {
        response = await handleApi(request, env, url);
      } else if (url.pathname === "/admin" || url.pathname === "/admin/") {
        response = await env.ASSETS.fetch(new Request(new URL("/admin.html", url), request));
      } else {
        response = await env.ASSETS.fetch(request);
      }
    } catch (error) {
      response = url.pathname.startsWith("/api/") ? fail("Terjadi kesalahan server.", 500) : new Response("Terjadi kesalahan server.", { status: 500 });
    }
    const headers = new Headers(response.headers);
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
    headers.set("X-Frame-Options", "DENY");
    headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  }
};
