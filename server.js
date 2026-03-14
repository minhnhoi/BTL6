
require("dotenv").config();
const express = require("express");
const multer = require("multer");
const cloudinaryLib = require("cloudinary").v2;
const streamifier = require("streamifier");
const axios = require("axios");
const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");
const crypto = require("crypto");
const dns = require("dns").promises;
const net = require("net");

const app = express();
const port = Number(process.env.PORT || 3000);
const ROOT_DIR = __dirname;
const PUBLIC_DIR = path.join(ROOT_DIR, "public");
const MAX_FILES_LIMIT = 50;
const LEGACY_FACE_DB_PATH = path.join(ROOT_DIR, "face_db.json");
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 100);
const FACE_UNLOCK_THRESHOLD = Number(process.env.FACE_UNLOCK_THRESHOLD || 0.44);
const SESSION_COOKIE_NAME = "admin_sid";
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 1000 * 60 * 60 * 12);
const FACE_RESET_TTL_MS = Number(process.env.FACE_RESET_TTL_MS || 1000 * 60 * 2);
const UPLOAD_BURST_WINDOW_MS = Number(process.env.UPLOAD_BURST_WINDOW_MS || 60 * 1000);
const UPLOAD_BURST_LIMIT = Number(process.env.UPLOAD_BURST_LIMIT || 12);
const UPLOAD_CONCURRENT_LIMIT = Number(process.env.UPLOAD_CONCURRENT_LIMIT || 4);
const UPLOAD_BLOCK_DURATION_MS = Number(process.env.UPLOAD_BLOCK_DURATION_MS || 1000 * 60 * 60 * 24 * 365 * 5);

app.disable("x-powered-by");
app.set("trust proxy", true);

function buildCsp() {
  return [
    "default-src 'self' https: data: blob:",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "form-action 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://justadudewhohacks.github.io",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:",
    "img-src 'self' data: blob: https:",
    "media-src 'self' data: blob: https:",
    "connect-src 'self' https://res.cloudinary.com https://api.cloudinary.com https://generativelanguage.googleapis.com https://justadudewhohacks.github.io https://cdn.jsdelivr.net",
    "worker-src 'self' blob:",
  ].join("; ");
}

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Permissions-Policy",
    "camera=(self), microphone=(), geolocation=(), payment=(), usb=()"
  );
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Origin-Agent-Cluster", "?1");
  if (req.secure || String(req.headers["x-forwarded-proto"] || "") === "https") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  res.setHeader("Content-Security-Policy", buildCsp());
  next();
});

app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: false, limit: "20mb" }));

app.use(rejectBlockedIp);

app.use(
  express.static(PUBLIC_DIR, {
    index: false,
    dotfiles: "deny",
    fallthrough: true,
    maxAge: "1h",
    setHeaders(res, filePath) {
      if (/\.(html?)$/i.test(filePath)) {
        res.setHeader("Cache-Control", "no-store");
      }
    },
  })
);

app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  return (
    (typeof xff === "string" && xff.split(",")[0].trim()) ||
    req.ip ||
    req.socket?.remoteAddress ||
    ""
  );
}

function getForwardedForRaw(req) {
  const xff = req.headers["x-forwarded-for"];
  return typeof xff === "string" ? xff : "";
}

function getNetworkKeyFromIp(ip) {
  if (!ip) return "unknown";
  const v4 = ip.includes("::ffff:") ? ip.split("::ffff:")[1] : ip;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v4)) {
    const parts = v4.split(".");
    return `${parts[0]}.${parts[1]}.${parts[2]}.*`;
  }
  const seg = ip.split(":").filter(Boolean);
  return `${seg.slice(0, 4).join(":")}::/64`;
}

function makeRequestId() {
  return `${Date.now().toString(36)}-${crypto.randomBytes(5).toString("hex")}`;
}

async function connectMongo() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.warn("⚠️ MONGODB_URI chưa cấu hình -> các tính năng Mongo/FaceID sẽ không hoạt động.");
    return;
  }
  try {
    await mongoose.connect(uri, {
      autoIndex: true,
      serverSelectionTimeoutMS: 8000,
    });
    console.log("✅ MongoDB connected");
  } catch (e) {
    console.error("❌ MongoDB connect error:", e.message);
  }
}

const AccessLogSchema = new mongoose.Schema(
  {
    ts: { type: Date, default: Date.now, index: true },
    ip: { type: String, index: true },
    method: String,
    path: String,
    status: Number,
    durationMs: Number,
    userAgent: String,
    referer: String,
    acceptLanguage: String,
    client: {
      timezone: String,
      platform: String,
      language: String,
      screen: { w: Number, h: Number },
      deviceMemory: Number,
      hardwareConcurrency: Number,
      touch: Boolean,
      deviceName: String,
    },
  },
  { versionKey: false }
);
const AccessLog =
  mongoose.models.AccessLog || mongoose.model("AccessLog", AccessLogSchema);

const NetworkAggSchema = new mongoose.Schema(
  {
    networkKey: { type: String, index: true },
    lastIp: { type: String, index: true },
    lastXff: String,
    firstSeen: { type: Date, default: Date.now, index: true },
    lastSeen: { type: Date, default: Date.now, index: true },
    hits: { type: Number, default: 0 },
    paths: { type: Map, of: Number, default: {} },
    userAgents: { type: [String], default: [] },
    lastEvent: {
      ts: Date,
      requestId: String,
      ip: String,
      xff: String,
      method: String,
      path: String,
      status: Number,
      durationMs: Number,
      ua: String,
      referer: String,
      acceptLanguage: String,
    },
    events: {
      type: [
        {
          ts: Date,
          requestId: String,
          ip: String,
          xff: String,
          method: String,
          path: String,
          status: Number,
          durationMs: Number,
          ua: String,
          referer: String,
          acceptLanguage: String,
        },
      ],
      default: [],
    },
    client: {
      timezone: String,
      platform: String,
      language: String,
      screen: { w: Number, h: Number },
      deviceMemory: Number,
      hardwareConcurrency: Number,
      touch: Boolean,
      deviceName: String,
    },
  },
  { versionKey: false }
);
NetworkAggSchema.index(
  { lastSeen: 1 },
  { expireAfterSeconds: 60 * 60 * 24 * 30 }
);
const NetworkAgg =
  mongoose.models.NetworkAgg || mongoose.model("NetworkAgg", NetworkAggSchema);

const UploadCounterSchema = new mongoose.Schema(
  {
    key: { type: String, unique: true, index: true },
    value: { type: Number, default: 0 },
  },
  { versionKey: false }
);
const UploadCounter =
  mongoose.models.UploadCounter ||
  mongoose.model("UploadCounter", UploadCounterSchema);

const BlockedIpSchema = new mongoose.Schema(
  {
    ip: { type: String, required: true, unique: true, index: true },
    networkKey: { type: String, index: true },
    status: { type: String, default: "blocked", index: true },
    reason: { type: String, default: "UPLOAD_ABUSE" },
    blockedAt: { type: Date, default: Date.now, index: true },
    blockedUntil: { type: Date, index: true },
    unblockAt: { type: Date },
    requestCount: { type: Number, default: 0 },
    concurrentAtDetection: { type: Number, default: 0 },
    route: String,
    method: String,
    userAgent: String,
    referer: String,
    acceptLanguage: String,
    forwardedFor: String,
    device: {
      timezone: String,
      platform: String,
      language: String,
      screen: { w: Number, h: Number },
      deviceMemory: Number,
      hardwareConcurrency: Number,
      touch: Boolean,
      deviceName: String,
    },
    lastEvent: { type: Object, default: {} },
    notes: { type: String, default: "" },
  },
  { versionKey: false }
);
const BlockedIp =
  mongoose.models.BlockedIp || mongoose.model("BlockedIp", BlockedIpSchema);

const FaceIdSchema = new mongoose.Schema(
  {
    label: { type: String, required: true, unique: true, index: true },
    descriptorsEnc: { type: String, required: false },
    descriptorCount: { type: Number, default: 0 },
    vectorLength: { type: Number, default: 0 },
    migratedFrom: { type: String, default: "mongo" },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  { versionKey: false, strict: false }
);
const FaceId = mongoose.models.FaceId || mongoose.model("FaceId", FaceIdSchema);

async function incUploadCounter(delta = 1) {
  if (mongoose.connection?.readyState !== 1) return null;
  const doc = await UploadCounter.findOneAndUpdate(
    { key: "lifetime_upload_count" },
    { $inc: { value: delta } },
    { upsert: true, new: true }
  );
  return doc?.value ?? 0;
}

async function getUploadCounter() {
  if (mongoose.connection?.readyState !== 1) return 0;
  const doc = await UploadCounter.findOne({ key: "lifetime_upload_count" }).lean();
  return doc?.value ?? 0;
}

app.use((req, res, next) => {
  const start = Date.now();
  const requestId = makeRequestId();
  res.setHeader("x-request-id", requestId);

  res.on("finish", async () => {
    try {
      if (mongoose.connection?.readyState !== 1) return;

      const ip = getClientIp(req);
      const xffRaw = getForwardedForRaw(req);
      const networkKey = getNetworkKeyFromIp(ip);
      const durationMs = Date.now() - start;
      const reqPath = req.path || req.originalUrl || req.url;
      const ua = req.headers["user-agent"] || "";
      const referer = req.headers["referer"] || "";
      const acceptLanguage = req.headers["accept-language"] || "";
      const now = new Date();

      const event = {
        ts: now,
        requestId,
        ip,
        xff: xffRaw,
        method: req.method,
        path: reqPath,
        status: res.statusCode,
        durationMs,
        ua,
        referer,
        acceptLanguage,
      };

      await NetworkAgg.updateOne(
        { networkKey },
        {
          $setOnInsert: { firstSeen: now, networkKey },
          $set: {
            lastSeen: now,
            lastIp: ip,
            lastXff: xffRaw,
            lastEvent: event,
          },
          $inc: {
            hits: 1,
            [`paths.${reqPath}`]: 1,
          },
          ...(ua ? { $addToSet: { userAgents: ua } } : {}),
          $push: {
            events: {
              $each: [event],
              $slice: -50,
            },
          },
        },
        { upsert: true }
      );

      await AccessLog.create({
        ts: now,
        ip,
        method: req.method,
        path: reqPath,
        status: res.statusCode,
        durationMs,
        userAgent: ua,
        referer,
        acceptLanguage,
      });
    } catch (e) {
      console.warn("network agg log error:", e.message);
    }
  });

  next();
});

app.post("/telemetry/client", async (req, res) => {
  try {
    if (mongoose.connection?.readyState !== 1) {
      return res.json({ success: false, message: "Mongo chưa sẵn sàng" });
    }

    const body = req.body || {};
    const ip = getClientIp(req);
    const xffRaw = getForwardedForRaw(req);
    const networkKey = getNetworkKeyFromIp(ip);
    const now = new Date();

    await NetworkAgg.updateOne(
      { networkKey },
      {
        $setOnInsert: { firstSeen: now, networkKey },
        $set: {
          lastSeen: now,
          lastIp: ip,
          lastXff: xffRaw,
          client: {
            timezone: body.timezone,
            platform: body.platform,
            language: body.language,
            screen: body.screen,
            deviceMemory: body.deviceMemory,
            hardwareConcurrency: body.hardwareConcurrency,
            touch: body.touch,
            deviceName: body.deviceName,
          },
        },
      },
      { upsert: true }
    );

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

const accounts = [
  {
    name: "Kho Chính (Cloudinary main)",
    cloud_name: process.env.CLOUD_NAME_1,
    api_key: process.env.CLOUD_API_KEY_1,
    api_secret: process.env.CLOUD_API_SECRET_1,
  },
  {
    name: "Kho Dự Phòng 1 (Cloudinary 1)",
    cloud_name: process.env.CLOUD_NAME_2,
    api_key: process.env.CLOUD_API_KEY_2,
    api_secret: process.env.CLOUD_API_SECRET_2,
  },
  {
    name: "Kho Dự Phòng 2 (Cloudinary 2)",
    cloud_name: process.env.CLOUD_NAME_3,
    api_key: process.env.CLOUD_API_KEY_3,
    api_secret: process.env.CLOUD_API_SECRET_3,
  },
  {
    name: "Kho Dự Phòng 3 (Cloudinary 3)",
    cloud_name: process.env.CLOUD_NAME_4,
    api_key: process.env.CLOUD_API_KEY_4,
    api_secret: process.env.CLOUD_API_SECRET_4,
  },
];

function getAccount(index) {
  const idx = Number(index ?? 0);
  const acc = accounts[idx];
  if (!Number.isInteger(idx) || idx < 0 || idx >= accounts.length) return null;
  if (!acc || !acc.cloud_name || !acc.api_key || !acc.api_secret) return null;
  return { ...acc, index: idx };
}

let cloudinaryLock = Promise.resolve();

function withCloudinaryAccount(index, task) {
  const acc = getAccount(index);
  if (!acc) {
    const err = new Error("Lỗi cấu hình Cloudinary.");
    err.code = "INVALID_ACCOUNT";
    throw err;
  }

  const run = async () => {
    cloudinaryLib.config({
      cloud_name: acc.cloud_name,
      api_key: acc.api_key,
      api_secret: acc.api_secret,
    });
    return task(acc);
  };

  const next = cloudinaryLock.then(run, run);
  cloudinaryLock = next.catch(() => { });
  return next;
}

function pbkdf2HashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const iterations = 210000;
  const digest = "sha512";
  const keylen = 64;
  const hash = crypto
    .pbkdf2Sync(password, salt, iterations, keylen, digest)
    .toString("hex");
  return `pbkdf2$${digest}$${iterations}$${salt}$${hash}`;
}

function verifyAdminPassword(password) {
  const plain = process.env.ADMIN_PASSWORD || "";
  const hashed = process.env.ADMIN_PASSWORD_HASH || "";
  const value = String(password || "");

  if (hashed.startsWith("pbkdf2$")) {
    const parts = hashed.split("$");
    if (parts.length !== 5) return false;
    const [, digest, iterRaw, salt, storedHash] = parts;
    const iterations = Number(iterRaw);
    if (!digest || !iterations || !salt || !storedHash) return false;
    const derived = crypto
      .pbkdf2Sync(value, salt, iterations, Buffer.from(storedHash, "hex").length, digest)
      .toString("hex");
    const a = Buffer.from(derived, "hex");
    const b = Buffer.from(storedHash, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  if (!plain) return false;
  const a = Buffer.from(value);
  const b = Buffer.from(plain);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function parseCookies(cookieHeader) {
  const out = {};
  String(cookieHeader || "")
    .split(";")
    .map((v) => v.trim())
    .filter(Boolean)
    .forEach((pair) => {
      const idx = pair.indexOf("=");
      if (idx === -1) return;
      const key = decodeURIComponent(pair.slice(0, idx).trim());
      const value = decodeURIComponent(pair.slice(idx + 1).trim());
      out[key] = value;
    });
  return out;
}

const sessions = new Map();

function cleanupSessions() {
  const now = Date.now();
  for (const [sid, session] of sessions.entries()) {
    if (!session || session.expiresAt <= now) {
      sessions.delete(sid);
    }
  }
}
setInterval(cleanupSessions, 60 * 1000).unref();

function setSessionCookie(req, res, sid, expiresAt) {
  const isSecure =
    process.env.COOKIE_SECURE === "true" ||
    (process.env.COOKIE_SECURE !== "false" && req.secure);
  const parts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(sid)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${Math.max(1, Math.floor((expiresAt - Date.now()) / 1000))}`,
  ];
  if (isSecure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearSessionCookie(req, res) {
  const isSecure =
    process.env.COOKIE_SECURE === "true" ||
    (process.env.COOKIE_SECURE !== "false" && req.secure);
  const parts = [
    `${SESSION_COOKIE_NAME}=`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    "Max-Age=0",
  ];
  if (isSecure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function createAdminSession(req, res, extra = {}) {
  const currentSid = req.sessionId;
  if (currentSid) sessions.delete(currentSid);

  const sid = crypto.randomBytes(32).toString("hex");
  const session = {
    id: sid,
    isAdmin: true,
    createdAt: Date.now(),
    lastSeenAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL_MS,
    faceResetVerifiedUntil: 0,
    ...extra,
  };
  sessions.set(sid, session);
  setSessionCookie(req, res, sid, session.expiresAt);
  req.sessionId = sid;
  req.adminSession = session;
  return session;
}

function touchSession(req, res) {
  if (!req.adminSession || !req.sessionId) return;
  req.adminSession.lastSeenAt = Date.now();
  req.adminSession.expiresAt = Date.now() + SESSION_TTL_MS;
  setSessionCookie(req, res, req.sessionId, req.adminSession.expiresAt);
}

app.use((req, res, next) => {
  const cookies = parseCookies(req.headers.cookie || "");
  req.cookies = cookies;
  req.sessionId = null;
  req.adminSession = null;

  const sid = cookies[SESSION_COOKIE_NAME];
  if (sid) {
    const session = sessions.get(sid);
    if (session && session.expiresAt > Date.now()) {
      req.sessionId = sid;
      req.adminSession = session;
      session.lastSeenAt = Date.now();
    } else if (sid) {
      sessions.delete(sid);
      clearSessionCookie(req, res);
    }
  }

  next();
});

function getExpectedOrigin(req) {
  return `${req.protocol}://${req.get("host")}`;
}

function requireSameOrigin(req, res, next) {
  const origin = req.headers.origin;
  const referer = req.headers.referer;
  const expected = getExpectedOrigin(req);

  if (origin) {
    if (origin !== expected) {
      return res.status(403).json({ success: false, message: "Bad origin" });
    }
    return next();
  }

  if (referer) {
    try {
      const refererOrigin = new URL(referer).origin;
      if (refererOrigin !== expected) {
        return res.status(403).json({ success: false, message: "Bad referer" });
      }
    } catch (_) {
      return res.status(403).json({ success: false, message: "Bad referer" });
    }
  }

  return next();
}

function requireAdmin(req, res, next) {
  if (!req.adminSession || req.adminSession.isAdmin !== true) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  touchSession(req, res);
  next();
}

function requireRecentFaceReset(req, res, next) {
  if (!req.adminSession || req.adminSession.faceResetVerifiedUntil < Date.now()) {
    return res
      .status(403)
      .json({ success: false, message: "Face reset verification required" });
  }
  next();
}

const rateBuckets = new Map();

function isRateLimited(key, limit, windowMs) {
  const now = Date.now();
  const arr = rateBuckets.get(key) || [];
  const fresh = arr.filter((ts) => now - ts < windowMs);
  fresh.push(now);
  rateBuckets.set(key, fresh);
  return fresh.length > limit;
}

function buildRateKey(prefix, req) {
  return `${prefix}:${getClientIp(req)}`;
}

const ipBlockCache = new Map();
const uploadConcurrency = new Map();

function getCachedBlockedIp(ip) {
  const item = ipBlockCache.get(ip);
  if (!item) return null;
  if (item.blockedUntil && item.blockedUntil <= Date.now()) {
    ipBlockCache.delete(ip);
    return null;
  }
  return item;
}

function setBlockedIpCache(ip, payload) {
  if (!ip) return;
  ipBlockCache.set(ip, {
    blockedUntil: payload?.blockedUntil ? new Date(payload.blockedUntil).getTime() : null,
    reason: String(payload?.reason || "UPLOAD_ABUSE"),
  });
}

function beginTrackedUpload(ip) {
  const current = uploadConcurrency.get(ip) || 0;
  const next = current + 1;
  uploadConcurrency.set(ip, next);
  return next;
}

function endTrackedUpload(ip) {
  if (!ip) return 0;
  const current = uploadConcurrency.get(ip) || 0;
  const next = Math.max(0, current - 1);
  if (next <= 0) uploadConcurrency.delete(ip);
  else uploadConcurrency.set(ip, next);
  return next;
}

async function findBlockedIp(ip) {
  if (!ip) return null;
  const cached = getCachedBlockedIp(ip);
  if (cached) return cached;
  if (!isMongoReady()) return null;

  const now = new Date();
  const doc = await BlockedIp.findOne({
    ip,
    status: "blocked",
    $or: [{ blockedUntil: null }, { blockedUntil: { $gt: now } }],
  })
    .sort({ blockedAt: -1 })
    .lean();

  if (doc) setBlockedIpCache(ip, doc);
  return doc;
}

async function blockIpAndPersist(req, details = {}) {
  const ip = getClientIp(req);
  if (!ip) return null;

  const blockedUntil = new Date(Date.now() + UPLOAD_BLOCK_DURATION_MS);
  const networkKey = getNetworkKeyFromIp(ip);
  const xffRaw = getForwardedForRaw(req);
  let device = null;
  let lastEvent = {};

  if (isMongoReady()) {
    const networkDoc = await NetworkAgg.findOne({ networkKey }).lean().catch(() => null);
    if (networkDoc?.client) device = networkDoc.client;
    if (networkDoc?.lastEvent) lastEvent = networkDoc.lastEvent;
  }

  const payload = {
    ip,
    networkKey,
    status: "blocked",
    reason: String(details.reason || "UPLOAD_ABUSE"),
    blockedAt: new Date(),
    blockedUntil,
    requestCount: Number(details.requestCount || 0),
    concurrentAtDetection: Number(details.concurrent || 0),
    route: String(req.path || req.originalUrl || req.url || ""),
    method: String(req.method || ""),
    userAgent: String(req.headers["user-agent"] || ""),
    referer: String(req.headers.referer || ""),
    acceptLanguage: String(req.headers["accept-language"] || ""),
    forwardedFor: xffRaw,
    device: device || undefined,
    lastEvent,
    notes: String(details.notes || "Too many upload requests from one IP"),
  };

  setBlockedIpCache(ip, payload);

  if (isMongoReady()) {
    await BlockedIp.updateOne(
      { ip },
      {
        $set: payload,
        $setOnInsert: { unblockAt: null },
      },
      { upsert: true }
    );
  }

  return payload;
}

function getUploadBurstCount(req) {
  const key = buildRateKey("upload-burst", req);
  const now = Date.now();
  const arr = rateBuckets.get(key) || [];
  const fresh = arr.filter((ts) => now - ts < UPLOAD_BURST_WINDOW_MS);
  fresh.push(now);
  rateBuckets.set(key, fresh);
  return fresh.length;
}

async function enforceUploadSecurity(req, res, next) {
  try {
    const ip = getClientIp(req);
    const blocked = await findBlockedIp(ip);
    if (blocked) {
      return res.status(403).json({
        success: false,
        message: "IP này đã bị khóa do nghi ngờ tấn công upload.",
      });
    }

    const requestCount = getUploadBurstCount(req);
    const concurrent = beginTrackedUpload(ip);
    req.__trackedUploadIp = ip;

    if (requestCount > UPLOAD_BURST_LIMIT || concurrent > UPLOAD_CONCURRENT_LIMIT) {
      await blockIpAndPersist(req, {
        reason: requestCount > UPLOAD_BURST_LIMIT ? "UPLOAD_BURST_LIMIT" : "UPLOAD_CONCURRENT_LIMIT",
        requestCount,
        concurrent,
        notes: `Blocked after upload burst=${requestCount}, concurrent=${concurrent}`,
      });
      endTrackedUpload(ip);
      req.__trackedUploadIp = null;
      return res.status(429).json({
        success: false,
        message: "Phát hiện upload bất thường. IP đã bị khóa.",
      });
    }

    const release = () => {
      if (req.__trackedUploadIp) {
        endTrackedUpload(req.__trackedUploadIp);
        req.__trackedUploadIp = null;
      }
    };
    res.on("finish", release);
    res.on("close", release);
    next();
  } catch (e) {
    if (req.__trackedUploadIp) {
      endTrackedUpload(req.__trackedUploadIp);
      req.__trackedUploadIp = null;
    }
    res.status(500).json({ success: false, message: "Upload security error: " + e.message });
  }
}

async function rejectBlockedIp(req, res, next) {
  try {
    const blocked = await findBlockedIp(getClientIp(req));
    if (blocked) {
      return res.status(403).json({
        success: false,
        message: "IP này đã bị khóa do hoạt động bất thường.",
      });
    }
    next();
  } catch (e) {
    next(e);
  }
}

function isMongoReady() {
  return mongoose.connection?.readyState === 1;
}

function getFaceStoreKeyMaterial() {
  return (
    process.env.FACE_ID_ENCRYPTION_KEY ||
    process.env.FACE_DB_BACKUP_KEY ||
    process.env.SESSION_SECRET ||
    process.env.ADMIN_PASSWORD_HASH ||
    process.env.ADMIN_PASSWORD ||
    "change-me-face-store-key"
  );
}

function encryptFaceDescriptors(descriptors) {
  const secret = getFaceStoreKeyMaterial();
  const iv = crypto.randomBytes(12);
  const key = crypto.createHash("sha256").update(String(secret)).digest();
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(descriptors), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    v: 1,
    alg: "aes-256-gcm",
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: ciphertext.toString("base64"),
  });
}

function decryptFaceDescriptors(raw) {
  const payload = JSON.parse(String(raw || "{}"));
  const secret = getFaceStoreKeyMaterial();
  const key = crypto.createHash("sha256").update(String(secret)).digest();
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(payload.iv, "base64")
  );
  decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(payload.data, "base64")),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString("utf8"));
}

function normalizeDescriptorVector(input) {
  if (!Array.isArray(input)) return null;
  const arr = input.map((value) => Number(value));
  if (arr.length < 64 || arr.some((value) => !Number.isFinite(value))) {
    return null;
  }
  return arr;
}

function normalizeDescriptorBatch(input) {
  if (!Array.isArray(input)) return [];
  return input.map(normalizeDescriptorVector).filter(Boolean);
}

async function migrateLegacyFaceDbFileToMongo() {
  if (!isMongoReady() || !fs.existsSync(LEGACY_FACE_DB_PATH)) return;

  try {
    const raw = fs.readFileSync(LEGACY_FACE_DB_PATH, "utf8");
    const parsed = JSON.parse(raw || "[]");
    const legacyAdmin = Array.isArray(parsed)
      ? parsed.find((item) => item?.label === "Admin")
      : null;

    if (!legacyAdmin) return;

    const alreadyExists = await FaceId.findOne({ label: "Admin" }).lean();
    if (!alreadyExists) {
      await writeStoredFaceData("Admin", legacyAdmin.descriptors, { migratedFrom: "legacy-file" });
      console.log("✅ Đã migrate FaceID từ file local sang MongoDB");
    }

    const archivedPath = `${LEGACY_FACE_DB_PATH}.migrated`;
    if (!fs.existsSync(archivedPath)) {
      fs.renameSync(LEGACY_FACE_DB_PATH, archivedPath);
    } else {
      fs.unlinkSync(LEGACY_FACE_DB_PATH);
    }
  } catch (error) {
    console.error("⚠️ Không thể migrate FaceID local sang MongoDB:", error.message);
  }
}

async function readStoredFaceData() {
  if (!isMongoReady()) return [];

  const doc = await FaceId.findOne({ label: "Admin" }).lean();
  if (!doc) return [];

  let descriptors = [];
  if (typeof doc.descriptorsEnc === "string" && doc.descriptorsEnc.trim()) {
    descriptors = normalizeDescriptorBatch(decryptFaceDescriptors(doc.descriptorsEnc));
  } else if (Array.isArray(doc.descriptors)) {
    descriptors = normalizeDescriptorBatch(doc.descriptors);
  }

  if (!descriptors.length) return [];
  return [{ label: String(doc.label || "Admin"), descriptors }];
}

async function writeStoredFaceData(label, descriptors, options = {}) {
  if (!isMongoReady()) {
    throw new Error("FACE_STORE_UNAVAILABLE");
  }

  const normalized = normalizeDescriptorBatch(descriptors);
  if (!normalized.length) {
    throw new Error("INVALID_DESCRIPTOR");
  }

  const encrypted = encryptFaceDescriptors(normalized);
  await FaceId.updateOne(
    { label },
    {
      $set: {
        label,
        descriptorsEnc: encrypted,
        descriptorCount: normalized.length,
        vectorLength: normalized[0]?.length || 0,
        migratedFrom: String(options.migratedFrom || "mongo"),
        updatedAt: new Date(),
      },
      $setOnInsert: { createdAt: new Date() },
      $unset: { descriptors: "" },
    },
    { upsert: true }
  );

  return { mode: "mongo", count: normalized.length };
}

async function clearStoredFaceData() {
  if (!isMongoReady()) {
    throw new Error("FACE_STORE_UNAVAILABLE");
  }
  await FaceId.deleteOne({ label: "Admin" });
}

function euclideanDistance(a, b) {
  const len = Math.min(a.length, b.length);
  let sum = 0;
  for (let i = 0; i < len; i++) {
    const diff = Number(a[i] || 0) - Number(b[i] || 0);
    sum += diff * diff;
  }
  return Math.sqrt(sum);
}

async function verifyFaceDescriptor(descriptor) {
  const data = await readStoredFaceData();
  const admin = data.find((item) => item?.label === "Admin");
  if (!admin || !Array.isArray(admin.descriptors) || admin.descriptors.length === 0) {
    return { ok: false, reason: "NO_FACE_DATA" };
  }

  const incoming = Array.isArray(descriptor) ? descriptor.map(Number) : [];
  if (incoming.length < 64) {
    return { ok: false, reason: "INVALID_DESCRIPTOR" };
  }

  let bestDistance = Number.POSITIVE_INFINITY;
  for (const stored of admin.descriptors) {
    if (!Array.isArray(stored) || stored.length < 64) continue;
    const distance = euclideanDistance(incoming, stored);
    if (distance < bestDistance) bestDistance = distance;
  }

  return {
    ok: Number.isFinite(bestDistance) && bestDistance < FACE_UNLOCK_THRESHOLD,
    distance: bestDistance,
    threshold: FACE_UNLOCK_THRESHOLD,
  };
}

function isPrivateIp(ip) {
  const normalized = ip.startsWith("::ffff:") ? ip.slice(7) : ip;
  if (net.isIP(normalized) === 4) {
    const parts = normalized.split(".").map((v) => Number(v));
    const [a, b] = parts;
    return (
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a === 127 ||
      a === 0 ||
      (a === 169 && b === 254)
    );
  }
  if (net.isIP(normalized) === 6) {
    const lower = normalized.toLowerCase();
    return (
      lower === "::1" ||
      lower.startsWith("fc") ||
      lower.startsWith("fd") ||
      lower.startsWith("fe80")
    );
  }
  return false;
}

async function assertSafeRemoteUrl(input) {
  let parsed;
  try {
    parsed = new URL(String(input || ""));
  } catch (_) {
    throw new Error("URL không hợp lệ");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Chỉ cho phép http/https");
  }
  if (parsed.username || parsed.password) {
    throw new Error("URL chứa thông tin đăng nhập không được phép");
  }

  const host = parsed.hostname;
  if (!host) throw new Error("Thiếu hostname");
  const normalizedHost = host.toLowerCase();
  if (["localhost"].includes(normalizedHost)) {
    throw new Error("Hostname nội bộ không được phép");
  }
  if (net.isIP(normalizedHost) && isPrivateIp(normalizedHost)) {
    throw new Error("Địa chỉ IP nội bộ không được phép");
  }

  const records = await dns.lookup(normalizedHost, { all: true });
  if (!records.length) throw new Error("Không phân giải được hostname");
  for (const item of records) {
    if (isPrivateIp(item.address)) {
      throw new Error("Hostname trỏ tới mạng nội bộ");
    }
  }

  return parsed.toString();
}

function normalizeCollectionName(name) {
  const value = String(name || "");
  if (!/^[a-zA-Z0-9_.-]+$/.test(value)) return null;
  if (value.startsWith("system.")) return null;
  return value;
}

const BLOCKED_UPLOAD_MIME = new Set([
  "text/html",
  "application/xhtml+xml",
  "application/javascript",
  "text/javascript",
  "image/svg+xml",
  "application/x-sh",
  "application/x-msdownload",
  "application/x-dosexec",
]);

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: 1 },
  fileFilter(req, file, cb) {
    if (BLOCKED_UPLOAD_MIME.has(String(file.mimetype || "").toLowerCase())) {
      return cb(new Error("Loại file này không được phép upload."));
    }
    cb(null, true);
  },
});

app.get("/metrics/uploads", async (req, res) => {
  try {
    const count = await getUploadCounter();
    res.json({ success: true, count });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get("/get-count", async (req, res) => {
  try {
    const count = await getUploadCounter();
    res.json({ count });
  } catch (_) {
    res.json({ count: 0 });
  }
});

app.post("/save-count", requireSameOrigin, (req, res) => {
  res.json({ success: true });
});


app.get("/accounts", (req, res) => {
  const list = accounts
    .map((acc, index) => (acc.cloud_name ? { index, name: acc.name } : null))
    .filter(Boolean);
  res.json({ success: true, accounts: list });
});

app.get("/stats", async (req, res) => {
  const index = Number(req.query.index || 0);
  const acc = getAccount(index);

  if (!acc) {
    return res.json({
      success: true,
      isEmpty: true,
      totalFiles: 0,
      storage: { used: 0, total: 0, percent: 0 },
    });
  }

  try {
    const payload = await withCloudinaryAccount(index, async () => {
      const checkResult = await cloudinaryLib.search
        .expression("resource_type:image OR resource_type:video OR resource_type:raw")
        .max_results(1)
        .execute();
      const totalFiles = checkResult.total_count;

      let usageData = { used: 0, total: 25, percent: 0 };
      try {
        const usageResult = await cloudinaryLib.api.usage();
        const usedCredits = usageResult.credits?.usage || 0;
        const limitCredits = usageResult.plan_limits?.credits || 25;
        usageData = {
          used: Number(usedCredits).toFixed(2),
          total: limitCredits,
          percent: Math.min(100, Math.round((usedCredits / limitCredits) * 100)),
        };
      } catch (_) { }

      return {
        success: true,
        totalFiles,
        storage: usageData,
        files: {
          remaining: Math.max(0, MAX_FILES_LIMIT - totalFiles),
          limit: MAX_FILES_LIMIT,
        },
      };
    });

    res.json(payload);
  } catch (error) {
    console.log(`Cổng ${index} lỗi xác thực hoặc mạng:`, error.message);
    res.json({
      success: true,
      isAuthError: true,
      totalFiles: 0,
      storage: { used: 0, total: 0, percent: 0 },
    });
  }
});

app.post("/upload", requireSameOrigin, enforceUploadSecurity, (req, res, next) => {
  upload.single("myFile")(req, res, (err) => {
    if (err) {
      return res.status(400).json({ success: false, message: err.message });
    }
    next();
  });
}, async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: "Chưa chọn file!" });
  }

  const index = Number(req.body.accountIndex || 0);
  const acc = getAccount(index);
  if (!acc) {
    return res.status(500).json({ success: false, message: "Lỗi cấu hình server." });
  }

  try {
    const result = await withCloudinaryAccount(index, async () => {
      return await new Promise((resolve, reject) => {
        const uploadStream = cloudinaryLib.uploader.upload_stream(
          {
            folder: "upload_master",
            resource_type: "auto",
            use_filename: true,
            unique_filename: true,
          },
          (error, uploadResult) => {
            if (error) return reject(error);
            resolve(uploadResult);
          }
        );
        streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
      });
    });

    res.json({
      success: true,
      data: {
        public_id: result.public_id,
        asset_id: result.asset_id,
        cloud_name: acc.cloud_name,
        filename: result.original_filename,
        secure_url: result.secure_url,
        resource_type: result.resource_type,
        format: result.format,
        bytes: result.bytes,
        created_at: result.created_at,
      },
    });

    incUploadCounter(1).catch(() => { });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post("/upload-url", requireSameOrigin, enforceUploadSecurity, async (req, res) => {
  const { url, accountIndex } = req.body || {};
  if (!url) return res.status(400).json({ success: false, message: "Thiếu URL" });

  const index = Number(accountIndex || 0);
  const acc = getAccount(index);
  if (!acc) return res.status(400).json({ success: false, message: "Lỗi cấu hình Cloud" });

  try {
    const safeUrl = await assertSafeRemoteUrl(url);
    const result = await withCloudinaryAccount(index, async () => {
      return await cloudinaryLib.uploader.upload(safeUrl, {
        folder: "upload_master_url",
        resource_type: "auto",
      });
    });

    res.json({
      success: true,
      data: {
        public_id: result.public_id,
        asset_id: result.asset_id,
        cloud_name: acc.cloud_name,
        filename: result.original_filename || "url_upload",
        secure_url: result.secure_url,
        resource_type: result.resource_type,
        format: result.format,
        bytes: result.bytes,
        created_at: result.created_at,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Lỗi: " + error.message });
  }
});

async function getFilesHandler(req, res, indexParam) {
  const index = Number(indexParam ?? req.query.index ?? 0);
  const acc = getAccount(index);

  if (!acc) {
    return res.json({
      success: true,
      files: [],
      message: "Cổng này chưa được kết nối hoặc cấu hình sai.",
    });
  }

  try {
    const resources = await withCloudinaryAccount(index, async () => {
      const result = await cloudinaryLib.search
        .expression("resource_type:image OR resource_type:video OR resource_type:raw")
        .sort_by("created_at", "desc")
        .max_results(500)
        .execute();
      return result.resources;
    });

    res.json({ success: true, files: resources });
  } catch (e) {
    console.error(`Lỗi lấy danh sách file (Cổng ${index}):`, e.message);
    res.json({ success: false, message: e.message, files: [] });
  }
}

app.get("/files", (req, res) => getFilesHandler(req, res));

app.post("/admin/login", requireSameOrigin, async (req, res) => {
  const key = buildRateKey("admin-login", req);
  if (isRateLimited(key, 10, 15 * 60 * 1000)) {
    return res.status(429).json({ success: false, message: "Thử lại sau." });
  }

  const { password } = req.body || {};
  if (!verifyAdminPassword(password)) {
    return res.status(401).json({ success: false, message: "Sai mật khẩu Admin" });
  }

  createAdminSession(req, res);
  return res.json({ success: true, session: { authenticated: true } });
});

app.post("/admin/logout", requireSameOrigin, (req, res) => {
  if (req.sessionId) sessions.delete(req.sessionId);
  clearSessionCookie(req, res);
  res.json({ success: true });
});

app.get("/admin/session", (req, res) => {
  const authenticated = !!(req.adminSession && req.adminSession.isAdmin === true);
  if (authenticated) touchSession(req, res);
  res.setHeader("Cache-Control", "no-store");
  res.json({
    success: true,
    authenticated,
    expiresAt: authenticated ? req.adminSession.expiresAt : null,
  });
});

app.get("/admin/files/:index", requireAdmin, (req, res) => {
  return getFilesHandler(req, res, req.params.index);
});

app.delete("/admin/files/:index/:id", requireSameOrigin, requireAdmin, async (req, res) => {
  const index = Number(req.params.index);
  const acc = getAccount(index);
  if (!acc) {
    return res.status(400).json({ success: false, message: "Account không hợp lệ" });
  }

  const publicId = decodeURIComponent(req.params.id);

  try {
    let result = await withCloudinaryAccount(index, async () => {
      let output = await cloudinaryLib.uploader.destroy(publicId);
      if (output.result !== "ok") {
        output = await cloudinaryLib.uploader.destroy(publicId, { resource_type: "video" });
      }
      if (output.result !== "ok") {
        output = await cloudinaryLib.uploader.destroy(publicId, { resource_type: "raw" });
      }
      return output;
    });

    if (result.result === "ok" || result.result === "not found") {
      res.json({ success: true });
    } else {
      res.json({ success: false, message: result.result });
    }
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post("/admin/rename", requireSameOrigin, requireAdmin, async (req, res) => {
  const { accountIndex, fileId, newName } = req.body || {};
  const index = Number(accountIndex);
  const acc = getAccount(index);
  if (!acc) {
    return res.status(400).json({ success: false, message: "Account không hợp lệ" });
  }

  const safeName = String(newName || "").trim().replace(/\s+/g, "_");
  if (!safeName || safeName.length > 180 || !/^[a-zA-Z0-9/_-]+$/.test(safeName)) {
    return res.status(400).json({ success: false, message: "Tên file không hợp lệ" });
  }

  try {
    const result = await withCloudinaryAccount(index, async () => {
      return cloudinaryLib.uploader.rename(fileId, safeName);
    });
    res.json({ success: true, data: result });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post("/admin/delete-batch", requireSameOrigin, requireAdmin, async (req, res) => {
  const { accountIndex, files } = req.body || {};
  const index = Number(accountIndex);
  const acc = getAccount(index);
  if (!acc) {
    return res.status(400).json({ success: false, message: "Account không hợp lệ" });
  }

  if (!Array.isArray(files) || files.length === 0) {
    return res.json({ success: false, message: "Chưa chọn file nào." });
  }

  const batch = files.slice(0, 200);

  try {
    const deletedCount = await withCloudinaryAccount(index, async () => {
      let count = 0;
      for (const file of batch) {
        try {
          const type = ["image", "video", "raw"].includes(file?.type)
            ? file.type
            : "image";
          await cloudinaryLib.uploader.destroy(String(file.id || ""), {
            resource_type: type,
          });
          count++;
        } catch (err) {
          console.error(`Lỗi xóa file ${file?.id}:`, err.message);
        }
      }
      return count;
    });

    res.json({ success: true, count: deletedCount });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.get("/admin/stats-all", requireAdmin, async (req, res) => {
  try {
    const results = [];

    for (let i = 0; i < accounts.length; i++) {
      const acc = accounts[i];
      if (!acc?.cloud_name || !acc.api_key || !acc.api_secret) {
        results.push({
          index: i,
          name: acc?.name || `Server ${i + 1}`,
          percent: 0,
          usedGB: 0,
          totalGB: 0,
          status: "empty",
        });
        continue;
      }

      try {
        const payload = await withCloudinaryAccount(i, async () => {
          const checkCount = await cloudinaryLib.search
            .expression("resource_type:image OR resource_type:video OR resource_type:raw")
            .max_results(1)
            .execute();

          const realTotalFiles = checkCount.total_count;
          const usageResult = await cloudinaryLib.api.usage();
          let rawUsed = usageResult.credits?.usage || 0;
          const total = usageResult.plan_limits?.credits || 25;

          if (realTotalFiles === 0) rawUsed = 0;
          const used = Math.max(0, rawUsed);
          const percent = Number(((used / total) * 100).toFixed(2));

          return {
            index: i,
            name: acc.name,
            usedGB: used.toFixed(2),
            totalGB: total,
            percent,
            status: "online",
          };
        });

        results.push(payload);
      } catch (err) {
        console.error(`Lỗi check stats server ${i}:`, err.message);
        results.push({
          index: i,
          name: acc.name,
          percent: 0,
          usedGB: 0,
          totalGB: 0,
          status: "error",
          message: "Lỗi kết nối",
        });
      }
    }

    res.json({ success: true, servers: results });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post("/admin/empty-trash/:index", requireSameOrigin, requireAdmin, (req, res) => {
  res.json({ success: true, message: "Cloudinary tự động quản lý thùng rác." });
});

app.get("/admin/mongo/collections", requireAdmin, async (req, res) => {
  if (mongoose.connection?.readyState !== 1) {
    return res.json({ success: false, message: "Mongo chưa sẵn sàng" });
  }

  try {
    const cols = await mongoose.connection.db.listCollections().toArray();
    res.json({
      success: true,
      collections: cols
        .map((c) => c.name)
        .filter((name) => !String(name).startsWith("system."))
        .sort(),
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get("/admin/mongo/:collection", requireAdmin, async (req, res) => {
  if (mongoose.connection?.readyState !== 1) {
    return res.json({ success: false, message: "Mongo chưa sẵn sàng" });
  }

  const collection = normalizeCollectionName(req.params.collection);
  if (!collection) {
    return res.status(400).json({ success: false, message: "Tên collection không hợp lệ" });
  }

  const limit = Math.min(Math.max(parseInt(req.query.limit || "50", 10), 1), 200);
  const skip = Math.max(parseInt(req.query.skip || "0", 10), 0);

  try {
    const col = mongoose.connection.db.collection(collection);
    const docs = await col.find({}).sort({ _id: -1 }).skip(skip).limit(limit).toArray();
    const out = docs.map((d) => ({ ...d, _id: d?._id?.toString?.() || d._id }));
    res.json({ success: true, data: out, limit, skip });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.delete(
  "/admin/mongo/:collection/:id",
  requireSameOrigin,
  requireAdmin,
  async (req, res) => {
    if (mongoose.connection?.readyState !== 1) {
      return res.json({ success: false, message: "Mongo chưa sẵn sàng" });
    }

    const collection = normalizeCollectionName(req.params.collection);
    const id = req.params.id;

    if (!collection) {
      return res.status(400).json({ success: false, message: "Tên collection không hợp lệ" });
    }

    try {
      const col = mongoose.connection.db.collection(collection);
      const _id = mongoose.Types.ObjectId.isValid(id)
        ? new mongoose.Types.ObjectId(id)
        : id;

      const result = await col.deleteOne({ _id });
      res.json({ success: true, deletedCount: result.deletedCount || 0 });
    } catch (e) {
      res.status(500).json({ success: false, message: e.message });
    }
  }
);

app.get("/face-id/status", async (req, res) => {
  try {
    const available = isMongoReady();
    const data = available ? await readStoredFaceData() : [];
    const hasFace = data.some(
      (item) => item?.label === "Admin" && Array.isArray(item?.descriptors) && item.descriptors.length
    );
    res.setHeader("Cache-Control", "no-store");
    res.json({
      success: true,
      available,
      storage: "mongodb",
      hasFace,
      authenticated: !!(req.adminSession && req.adminSession.isAdmin),
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get("/face-id/load", async (req, res) => {
  try {
    if (!req.adminSession || req.adminSession.isAdmin !== true) {
      return res.json({ success: true, available: isMongoReady(), data: [] });
    }
    if (!isMongoReady()) {
      return res.status(503).json({
        success: false,
        available: false,
        message: "FACE_STORE_UNAVAILABLE",
        data: [],
      });
    }
    const data = await readStoredFaceData();
    return res.json({
      success: true,
      available: true,
      storage: "mongodb",
      data: data.map((item) => ({
        label: item.label,
        descriptors: item.descriptors,
      })),
    });
  } catch (e) {
    console.error("FaceID load error:", e);
    return res.json({ success: true, available: isMongoReady(), data: [] });
  }
});

app.post("/face-id/verify", requireSameOrigin, async (req, res) => {
  const key = buildRateKey("face-verify", req);
  if (isRateLimited(key, 30, 5 * 60 * 1000)) {
    return res.status(429).json({ success: false, message: "Thử lại sau." });
  }

  if (!isMongoReady()) {
    return res.status(503).json({
      success: false,
      message: "FACE_STORE_UNAVAILABLE",
      storage: "mongodb",
    });
  }

  const descriptor = req.body?.descriptor;
  const intent = String(req.body?.intent || "login");

  try {
    const result = await verifyFaceDescriptor(descriptor);
    if (!result.ok) {
      return res.status(401).json({
        success: false,
        message: result.reason || "FACE_NOT_MATCHED",
        distance: result.distance,
        threshold: result.threshold,
      });
    }

    const session = createAdminSession(req, res);
    if (intent === "reset") {
      session.faceResetVerifiedUntil = Date.now() + FACE_RESET_TTL_MS;
    }

    return res.json({
      success: true,
      verified: true,
      storage: "mongodb",
      distance: result.distance,
      threshold: result.threshold,
    });
  } catch (e) {
    return res.status(500).json({ success: false, message: e.message });
  }
});

app.post("/face-id/register", requireSameOrigin, requireAdmin, async (req, res) => {
  if (!isMongoReady()) {
    return res.status(503).json({
      success: false,
      message: "FACE_STORE_UNAVAILABLE",
      storage: "mongodb",
    });
  }

  try {
    const { label, descriptors } = req.body || {};
    if (!label || !Array.isArray(descriptors) || descriptors.length === 0) {
      return res.status(400).json({ success: false, message: "INVALID_PAYLOAD" });
    }

    for (const d of descriptors) {
      if (!Array.isArray(d) || d.length < 64) {
        return res.status(400).json({ success: false, message: "INVALID_DESCRIPTOR" });
      }
    }

    const result = await writeStoredFaceData(String(label), descriptors);
    return res.json({
      success: true,
      storage: "mongodb",
      descriptorCount: result.count || 0,
      message: "Đã lưu FaceID vào MongoDB",
    });
  } catch (e) {
    console.error("FaceID register error:", e);
    const isStoreError = String(e.message || "").includes("FACE_STORE_UNAVAILABLE");
    return res
      .status(isStoreError ? 503 : 500)
      .json({ success: false, message: isStoreError ? "FACE_STORE_UNAVAILABLE" : "Lỗi Server lưu Face ID" });
  }
});

app.delete(
  "/face-id/clear",
  requireSameOrigin,
  requireAdmin,
  requireRecentFaceReset,
  async (req, res) => {
    if (!isMongoReady()) {
      return res.status(503).json({
        success: false,
        message: "FACE_STORE_UNAVAILABLE",
        storage: "mongodb",
      });
    }

    try {
      await clearStoredFaceData();
      if (req.adminSession) {
        req.adminSession.faceResetVerifiedUntil = 0;
      }
      return res.json({ success: true, storage: "mongodb", message: "Đã xóa dữ liệu FaceID" });
    } catch (e) {
      return res.status(500).json({ success: false, message: "Lỗi khi xóa dữ liệu" });
    }
  }
);

app.post("/admin/chatgpt", requireSameOrigin, requireAdmin, async (req, res) => {
  const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
  if (!apiKey) {
    return res.status(500).json({
      success: false,
      message: "Thiếu GEMINI_API_KEY trong .env",
    });
  }

  try {
    const { messages, model, temperature, structured } = req.body || {};
    const geminiModel =
      typeof model === "string" && model.trim().startsWith("gemini-")
        ? model.trim()
        : "gemini-2.5-flash";

    const safeText = (v) => (v === undefined || v === null ? "" : String(v));
    const arr = Array.isArray(messages)
      ? messages
      : [{ role: "user", content: safeText(req.body?.prompt || "") }];

    const systemText = arr
      .filter((m) => m && m.role === "system")
      .map((m) => safeText(m.content).trim())
      .filter(Boolean)
      .join("\n");

    const contents = arr
      .filter((m) => m && m.role !== "system")
      .map((m) => {
        const role = m.role === "assistant" ? "model" : "user";
        const text = safeText(m.content).trim() || " ";
        return { role, parts: [{ text }] };
      });

    const useStructured = structured === true;

    const securityReportSchema = {
      type: "object",
      additionalProperties: false,
      properties: {
        summary: { type: "string", description: "Tóm tắt tối đa 3 câu." },
        key_facts: {
          type: "array",
          items: { type: "string" },
          minItems: 3,
          maxItems: 8,
        },
        stats: {
          type: "object",
          additionalProperties: false,
          properties: {
            ip: { type: "string" },
            request_count: { type: "integer" },
            time_window_seconds: { type: "integer" },
            user_agent: { type: "string" },
            top_referers: {
              type: "array",
              items: { type: "string" },
              minItems: 0,
              maxItems: 8,
            },
            status_breakdown: {
              type: "object",
              additionalProperties: false,
              properties: {
                s2xx: { type: "integer" },
                s3xx: { type: "integer" },
                s4xx: { type: "integer" },
                s5xx: { type: "integer" },
              },
              required: ["s2xx", "s3xx", "s4xx", "s5xx"],
            },
          },
          required: [
            "ip",
            "request_count",
            "time_window_seconds",
            "user_agent",
            "top_referers",
            "status_breakdown",
          ],
        },
        admin_endpoints: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            properties: {
              path: { type: "string" },
              count: { type: "integer" },
              note: { type: "string" },
            },
            required: ["path", "count", "note"],
          },
        },
        risk: {
          type: "object",
          additionalProperties: false,
          properties: {
            level: { type: "string", enum: ["low", "medium", "high", "critical"] },
            score: { type: "integer", minimum: 0, maximum: 10 },
            reasons: {
              type: "array",
              items: { type: "string" },
              minItems: 2,
              maxItems: 8,
            },
          },
          required: ["level", "score", "reasons"],
        },
        actions: {
          type: "object",
          additionalProperties: false,
          properties: {
            immediate_24h: {
              type: "array",
              items: { type: "string" },
              minItems: 2,
              maxItems: 8,
            },
            short_7d: {
              type: "array",
              items: { type: "string" },
              minItems: 2,
              maxItems: 8,
            },
            long_30d: {
              type: "array",
              items: { type: "string" },
              minItems: 2,
              maxItems: 8,
            },
          },
          required: ["immediate_24h", "short_7d", "long_30d"],
        },
        limitations: {
          type: "array",
          items: { type: "string" },
          minItems: 1,
          maxItems: 6,
        },
      },
      required: [
        "summary",
        "key_facts",
        "stats",
        "admin_endpoints",
        "risk",
        "actions",
        "limitations",
      ],
    };

    const structuredSystem = useStructured
      ? [
        "Bạn là chuyên gia SOC. Hãy phân tích logs/ngữ cảnh người dùng cung cấp.",
        "Chỉ dùng thông tin có trong dữ liệu; nếu thiếu thì ghi rõ trong limitations, KHÔNG bịa.",
        "Trả về ĐÚNG JSON theo schema được yêu cầu. Không thêm văn bản ngoài JSON.",
      ].join("\n")
      : "";

    const body = {
      contents,
      generationConfig: {
        temperature: typeof temperature === "number" ? temperature : 0.3,
        ...(useStructured
          ? {
            responseMimeType: "application/json",
            responseJsonSchema: securityReportSchema,
          }
          : {}),
      },
      ...((systemText || structuredSystem)
        ? {
          systemInstruction: {
            role: "system",
            parts: [
              { text: [structuredSystem, systemText].filter(Boolean).join("\n") },
            ],
          },
        }
        : {}),
    };

    const modelPath = geminiModel.startsWith("models/")
      ? geminiModel
      : `models/${geminiModel}`;

    const url = `https://generativelanguage.googleapis.com/v1beta/${modelPath}:generateContent?key=${apiKey}`;

    const response = await axios.post(url, body, {
      headers: { "Content-Type": "application/json" },
      validateStatus: () => true,
    });

    const data = response.data || {};
    if (response.status < 200 || response.status >= 300) {
      return res.status(response.status).json({
        success: false,
        message: data?.error?.message || data?.message || "Gemini API error",
        raw: data,
      });
    }

    const text =
      (data?.candidates?.[0]?.content?.parts || [])
        .map((p) => p?.text || "")
        .join("") || "";

    if (useStructured) {
      try {
        const json = JSON.parse(text);
        return res.json({
          success: true,
          kind: "structured",
          data: json,
          usage: data?.usageMetadata,
          model: geminiModel,
        });
      } catch (e) {
        return res.json({
          success: true,
          kind: "text",
          reply: text || "(empty)",
          parseError: e.message,
          usage: data?.usageMetadata,
          model: geminiModel,
        });
      }
    }

    res.json({
      success: true,
      kind: "text",
      reply: text || "(empty)",
      usage: data?.usageMetadata,
      model: geminiModel,
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.listen(port, async () => {
  console.log(`✅ Server Cloudinary đang chạy tại http://localhost:${port}`);
  await connectMongo();
  await migrateLegacyFaceDbFileToMongo();
});

module.exports = { pbkdf2HashPassword };
