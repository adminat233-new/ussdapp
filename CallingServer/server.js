"use strict";

const crypto = require("node:crypto");
const express = require("express");
const { AccessToken, LiveKitAPI } = require("livekit-server-sdk");

const ROOM_TTL_MS = 4 * 60 * 60 * 1000;
const ROOM_LIMIT = 100;
const MAX_PARTICIPANTS = 8;
const TOKEN_TTL = "2h";
const RATE_WINDOW_MS = 60 * 1000;

function createCallingApp(options) {
  const config = options.config;
  const liveKitApi = options.liveKitApi;
  const accessTokenFactory = options.accessTokenFactory;
  const now = options.now || Date.now;
  const randomBytes = options.randomBytes || crypto.randomBytes;
  const rooms = new Map();
  const requests = new Map();
  const allowedOrigins = new Set((config.allowedOrigins || "").split(",")
    .map(function (origin) { return origin.trim(); })
    .filter(Boolean));
  const app = express();

  if (config.trustProxy) app.set("trust proxy", 1);
  app.disable("x-powered-by");
  app.use(function (req, res, next) {
    const origin = req.get("Origin");
    if (origin && allowedOrigins.has(origin)) {
      res.set("Access-Control-Allow-Origin", origin);
      res.set("Vary", "Origin");
      res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.set("Access-Control-Allow-Headers", "Content-Type");
    } else if (origin) {
      return res.status(403).json({ error: "origin_not_allowed" });
    }
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
  });
  app.use(express.json({ limit: "4kb", strict: true }));

  function rateLimit(key, limit) {
    const time = now();
    let bucket = requests.get(key);
    if (!bucket || time - bucket.started >= RATE_WINDOW_MS) {
      bucket = { started: time, count: 0 };
      requests.set(key, bucket);
    }
    bucket.count++;
    return bucket.count <= limit;
  }

  function requestKey(req) {
    return String(req.ip || req.socket.remoteAddress || "unknown");
  }

  function expireRooms() {
    const time = now();
    rooms.forEach(function (room, code) {
      if (room.expiresAt <= time) {
        rooms.delete(code);
        liveKitApi.room.deleteRoom(room.name).catch(function (error) {
          console.error("Could not remove expired call room:", error.message);
        });
      }
    });
    requests.forEach(function (bucket, key) {
      if (time - bucket.started >= RATE_WINDOW_MS) requests.delete(key);
    });
  }

  app.get("/healthz", function (req, res) {
    res.json({ ok: true });
  });

  app.post("/api/rooms", async function (req, res) {
    if (!rateLimit("room:" + requestKey(req), 5)) {
      return res.status(429).json({ error: "rate_limited" });
    }
    expireRooms();
    if (rooms.size >= ROOM_LIMIT) {
      return res.status(503).json({ error: "room_capacity_reached" });
    }
    const code = randomBytes(24).toString("hex");
    const name = "ussd-" + randomBytes(18).toString("hex");
    try {
      await liveKitApi.room.createRoom({
        name: name,
        emptyTimeout: Math.floor(ROOM_TTL_MS / 1000),
        maxParticipants: MAX_PARTICIPANTS
      });
    } catch (error) {
      console.error("Could not create call room:", error.message);
      return res.status(503).json({ error: "call_service_unavailable" });
    }
    const expiresAt = now() + ROOM_TTL_MS;
    rooms.set(code, { name: name, expiresAt: expiresAt });
    res.status(201).json({ invitationCode: code, expiresAt: new Date(expiresAt).toISOString() });
  });

  app.post("/api/token", async function (req, res) {
    if (!rateLimit("token:" + requestKey(req), 30)) {
      return res.status(429).json({ error: "rate_limited" });
    }
    const body = req.body || {};
    if (typeof body.invitationCode !== "string" ||
        !/^[a-f0-9]{48}$/.test(body.invitationCode)) {
      return res.status(400).json({ error: "invalid_invitation_code" });
    }
    if (typeof body.displayName !== "string") {
      return res.status(400).json({ error: "invalid_display_name" });
    }
    const displayName = body.displayName.trim();
    if (!displayName || displayName.length > 32 ||
        /[\u0000-\u001f\u007f]/.test(displayName)) {
      return res.status(400).json({ error: "invalid_display_name" });
    }
    const room = rooms.get(body.invitationCode);
    if (!room || room.expiresAt <= now()) {
      if (room) {
        rooms.delete(body.invitationCode);
        liveKitApi.room.deleteRoom(room.name).catch(function (error) {
          console.error("Could not remove expired call room:", error.message);
        });
      }
      return res.status(404).json({ error: "invitation_expired_or_unknown" });
    }
    const identity = "participant-" + randomBytes(12).toString("hex");
    try {
      const token = accessTokenFactory(config.livekitApiKey, config.livekitApiSecret, {
        identity: identity,
        name: displayName,
        ttl: TOKEN_TTL
      });
      token.addGrant({
        roomJoin: true,
        room: room.name,
        canPublish: true,
        canSubscribe: true,
        canPublishData: true
      });
      const jwt = await token.toJwt();
      res.json({
        serverUrl: config.livekitPublicUrl,
        token: jwt,
        identity: identity,
        roomName: room.name,
        participantLimit: MAX_PARTICIPANTS
      });
    } catch (error) {
      console.error("Could not issue call token:", error.message);
      res.status(503).json({ error: "call_service_unavailable" });
    }
  });

  const cleanup = setInterval(expireRooms, 60 * 1000);
  if (cleanup.unref) cleanup.unref();
  app.locals.close = function () { clearInterval(cleanup); };
  app.locals.rooms = rooms;
  app.use(function (error, req, res, next) {
    if (res.headersSent) return next(error);
    if (error && (error.type === "entity.too.large" || error.type === "entity.parse.failed")) {
      return res.status(400).json({ error: "invalid_request_body" });
    }
    console.error("Unhandled call API error:", error && error.message ? error.message : "unknown error");
    res.status(500).json({ error: "internal_error" });
  });
  return app;
}

function readConfig(env) {
  const config = {
    port: Number(env.CALL_API_PORT || 8080),
    allowedOrigins: env.CALL_ALLOWED_ORIGINS || "",
    trustProxy: env.CALL_TRUST_PROXY === "1",
    livekitPublicUrl: env.LIVEKIT_PUBLIC_URL || "",
    livekitInternalUrl: env.LIVEKIT_INTERNAL_URL || "",
    livekitApiKey: env.LIVEKIT_API_KEY || "",
    livekitApiSecret: env.LIVEKIT_API_SECRET || ""
  };
  if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
    throw new Error("CALL_API_PORT must be a valid TCP port.");
  }
  ["livekitPublicUrl", "livekitInternalUrl", "livekitApiKey", "livekitApiSecret"]
    .forEach(function (key) {
      if (!config[key]) throw new Error(key + " must be configured.");
    });
  if (!/^wss:\/\//.test(config.livekitPublicUrl)) {
    throw new Error("LIVEKIT_PUBLIC_URL must use wss://.");
  }
  return config;
}

function start() {
  const config = readConfig(process.env);
  const api = new LiveKitAPI({
    host: config.livekitInternalUrl,
    apiKey: config.livekitApiKey,
    secret: config.livekitApiSecret
  });
  const app = createCallingApp({
    config: config,
    liveKitApi: api,
    accessTokenFactory: function (key, secret, options) {
      return new AccessToken(key, secret, options);
    }
  });
  const server = app.listen(config.port, "0.0.0.0", function () {
    console.log("Call token API listening on port " + config.port);
  });
  function stop() {
    app.locals.close();
    server.close(function () { process.exit(0); });
    setTimeout(function () { process.exit(1); }, 10000).unref();
  }
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

if (require.main === module) {
  try { start(); }
  catch (error) {
    console.error("Call API configuration error:", error.message);
    process.exitCode = 1;
  }
}

module.exports = { createCallingApp: createCallingApp, readConfig: readConfig };
