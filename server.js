// ===== Word Compud — Server (Express) =====
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Konfigurasi ----------
const ADMIN_USER = process.env.ADMIN_USER || "admin";
// Default password: wordcompud123 — GANTI lewat env ADMIN_PASS saat deploy!
const ADMIN_PASS = process.env.ADMIN_PASS || "wordcompud123";
const SESSION_HOURS = 12;
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

// ---------- Data (JSON file database) ----------
const DATA_DIR = path.join(__dirname, "data");
const PRODUCTS_FILE = path.join(DATA_DIR, "products.json");
const UPLOAD_DIR = path.join(__dirname, "public", "uploads");

for (const dir of [DATA_DIR, UPLOAD_DIR]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// Produk awal: kosong — diisi lewat Admin Panel (admin.html)
if (!fs.existsSync(PRODUCTS_FILE)) {
  fs.writeFileSync(PRODUCTS_FILE, "[]");
}

function loadProducts() {
  try { return JSON.parse(fs.readFileSync(PRODUCTS_FILE, "utf8")); }
  catch { return []; }
}
function saveProducts(list) {
  fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(list, null, 2));
}

// ---------- Upload foto (multer) ----------
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      const ext = (path.extname(file.originalname) || ".jpg").toLowerCase();
      cb(null, `${Date.now()}-${crypto.randomBytes(6).toString("hex")}${ext}`);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024, files: 8 }, // max 5MB / foto, 8 foto sekali upload
  fileFilter: (req, file, cb) => {
    if (/^image\//.test(file.mimetype)) cb(null, true);
    else cb(new Error("Hanya file gambar yang diterima."));
  }
});

// ---------- Sessions (in-memory) ----------
const sessions = new Map(); // token -> { expires }

const ADMIN_HASH = (() => {
  const salt = crypto.createHmac("sha256", SECRET).update("salt-fixed").digest("hex").slice(0, 32);
  const hash = crypto.scryptSync(ADMIN_PASS, salt, 64).toString("hex");
  return `${salt}:${hash}`;
})();

function verifyPassword(pw) {
  const [salt, hash] = ADMIN_HASH.split(":");
  const test = crypto.scryptSync(pw, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(test, "hex"));
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  raw.split(";").forEach(pair => {
    const idx = pair.indexOf("=");
    if (idx > -1) out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

function isAuthed(req) {
  const token = parseCookies(req).vw_session;
  if (!token || !sessions.has(token)) return false;
  const s = sessions.get(token);
  if (Date.now() > s.expires) { sessions.delete(token); return false; }
  return true;
}

// ---------- Middleware ----------
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(UPLOAD_DIR));

// ---------- Auth routes ----------
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USER || !verifyPassword(String(password || ""))) {
    setTimeout(() => res.status(401).json({ ok: false, error: "Username atau password salah." }), 600);
    return;
  }
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { expires: Date.now() + SESSION_HOURS * 3600 * 1000 });
  res.setHeader("Set-Cookie",
    `vw_session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_HOURS * 3600}${process.env.NODE_ENV === "production" ? "; Secure" : ""}`);
  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  const token = parseCookies(req).vw_session;
  if (token) sessions.delete(token);
  res.setHeader("Set-Cookie", "vw_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0");
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  res.json({ ok: true, authed: isAuthed(req) });
});

// ---------- Product API ----------
app.get("/api/products", (req, res) => {
  res.json({ ok: true, data: loadProducts() });
});

// ---------- Admin API (wajib login) ----------
app.use("/api/admin", (req, res, next) => {
  if (!isAuthed(req)) return res.status(401).json({ ok: false, error: "Belum login." });
  next();
});

// Upload foto produk (multiple)
app.post("/api/admin/upload", (req, res) => {
  upload.array("photos", 8)(req, res, err => {
    if (err) {
      const msg = err.code === "LIMIT_FILE_SIZE" ? "File kegedean (max 5MB per foto)." :
                  err.code === "LIMIT_FILE_COUNT" ? "Max 8 foto sekali upload." : err.message;
      return res.status(400).json({ ok: false, error: msg });
    }
    if (!req.files || !req.files.length) {
      return res.status(400).json({ ok: false, error: "Tidak ada file terkirim." });
    }
    const urls = req.files.map(f => "/uploads/" + f.filename);
    res.json({ ok: true, urls });
  });
});

// Hapus file foto dari server
app.delete("/api/admin/photo", (req, res) => {
  const src = String((req.body || {}).src || "");
  if (!src.startsWith("/uploads/") || src.includes("..")) {
    return res.status(400).json({ ok: false, error: "Path tidak valid." });
  }
  const filePath = path.join(__dirname, "public", src);
  if (fs.existsSync(filePath)) {
    try { fs.unlinkSync(filePath); } catch { /* biarkan */ }
  }
  res.json({ ok: true });
});

function sanitizeItem(body) {
  let images = body.images;
  if (!Array.isArray(images)) images = [];
  images = images.filter(s => typeof s === "string" && s.startsWith("/uploads/") && !s.includes(".."));
  return {
    name: String(body.name || "").trim(),
    cat: String(body.cat || ""),
    price: parseInt(body.price, 10) || 0,
    rating: Math.min(5, Math.max(1, parseFloat(body.rating) || 4.5)),
    sold: parseInt(body.sold, 10) || 0,
    cond: ["ready", "best", "used"].includes(body.cond) ? body.cond : "ready",
    images
  };
}

app.post("/api/admin/products", (req, res) => {
  const item = sanitizeItem(req.body || {});
  if (!item.name || !item.cat) {
    return res.status(400).json({ ok: false, error: "name dan cat wajib diisi." });
  }
  const list = loadProducts();
  list.push(item);
  saveProducts(list);
  res.json({ ok: true, data: list });
});

app.put("/api/admin/products/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  const list = loadProducts();
  if (!list[id]) return res.status(404).json({ ok: false, error: "Produk tidak ditemukan." });
  const item = sanitizeItem(req.body || {});
  if (!item.name || !item.cat) {
    return res.status(400).json({ ok: false, error: "name dan cat wajib diisi." });
  }
  list[id] = item;
  saveProducts(list);
  res.json({ ok: true, data: list });
});

app.delete("/api/admin/products/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  const list = loadProducts();
  if (!list[id]) return res.status(404).json({ ok: false, error: "Produk tidak ditemukan." });

  // hapus file foto milik produk ini juga
  (list[id].images || []).forEach(src => {
    const filePath = path.join(__dirname, "public", src);
    if (src.startsWith("/uploads/") && fs.existsSync(filePath)) {
      try { fs.unlinkSync(filePath); } catch { /* biarkan */ }
    }
  });

  list.splice(id, 1);
  saveProducts(list);
  res.json({ ok: true, data: list });
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`⚡ Word Compud jalan di http://localhost:${PORT}`);
});
