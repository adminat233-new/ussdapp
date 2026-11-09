"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const express = require("express");
const request = require("supertest");
const { createCallingApp, readConfig } = require("./server");

const baseConfig = {
  port: 8080,
  allowedOrigins: "https://adminat233-new.github.io",
  trustProxy: false,
  livekitPublicUrl: "wss://calls.example.test",
  livekitInternalUrl: "http://127.0.0.1:7880",
  livekitApiKey: "test-key",
  livekitApiSecret: "test-secret"
};

function makeApp(options) {
  const created = [];
  const deleted = [];
  const app = createCallingApp({
    config: baseConfig,
    now: options && options.now,
    randomBytes: options && options.randomBytes,
    liveKitApi: {
      room: {
        createRoom: async function (room) { created.push(room); },
        deleteRoom: async function (room) { deleted.push(room); }
      }
    },
    accessTokenFactory: function (key, secret, identity) {
      assert.equal(key, "test-key");
      assert.equal(secret, "test-secret");
      return {
        addGrant: function (grant) {
          assert.equal(grant.roomJoin, true);
          assert.equal(grant.canPublish, true);
          assert.equal(grant.canSubscribe, true);
          assert.equal(grant.canPublishData, true);
        },
        toJwt: async function () { return "test-jwt"; }
      };
    }
  });
  return { app: app, created: created, deleted: deleted };
}

test("creates a random invite-backed room and issues a short-lived participant token", async function () {
  const instance = makeApp();
  try {
    const roomResponse = await request(instance.app)
      .post("/api/rooms")
      .send({});
    assert.equal(roomResponse.status, 201);
    assert.match(roomResponse.body.invitationCode, /^[a-f0-9]{48}$/);
    assert.equal(instance.created.length, 1);
    assert.equal(instance.created[0].maxParticipants, 8);

    const tokenResponse = await request(instance.app)
      .post("/api/token")
      .send({ invitationCode: roomResponse.body.invitationCode, displayName: "Test caller" });
    assert.equal(tokenResponse.status, 200);
    assert.equal(tokenResponse.body.token, "test-jwt");
    assert.equal(tokenResponse.body.serverUrl, baseConfig.livekitPublicUrl);
  } finally {
    instance.app.locals.close();
  }
});

test("rejects unknown invitations, invalid names, and untrusted browser origins", async function () {
  const instance = makeApp();
  try {
    const badOrigin = await request(instance.app)
      .post("/api/rooms")
      .set("Origin", "https://attacker.example")
      .send({});
    assert.equal(badOrigin.status, 403);

    const unknownInvite = await request(instance.app)
      .post("/api/token")
      .send({ invitationCode: "a".repeat(48), displayName: "Friend" });
    assert.equal(unknownInvite.status, 404);

    const room = await request(instance.app).post("/api/rooms").send({});
    const invalidName = await request(instance.app)
      .post("/api/token")
      .send({ invitationCode: room.body.invitationCode, displayName: "Bad\nName" });
    assert.equal(invalidName.status, 400);
  } finally {
    instance.app.locals.close();
  }
});

test("expires invitations after four hours", async function () {
  let time = 1000;
  const instance = makeApp({ now: function () { return time; } });
  try {
    const room = await request(instance.app).post("/api/rooms").send({});
    assert.equal(room.status, 201);
    time += 4 * 60 * 60 * 1000;

    const response = await request(instance.app)
      .post("/api/token")
      .send({ invitationCode: room.body.invitationCode, displayName: "Friend" });
    assert.equal(response.status, 404);
    assert.deepEqual(instance.deleted, [instance.created[0].name]);
  } finally {
    instance.app.locals.close();
  }
});

test("rate limits call creation after five invitations per minute", async function () {
  const instance = makeApp();
  try {
    for (let index = 0; index < 5; index++) {
      const response = await request(instance.app).post("/api/rooms").send({});
      assert.equal(response.status, 201);
    }

    const limited = await request(instance.app).post("/api/rooms").send({});
    assert.equal(limited.status, 429);
    assert.equal(instance.created.length, 5);
  } finally {
    instance.app.locals.close();
  }
});

test("validates server configuration and requires WSS for public signaling", function () {
  assert.throws(function () { readConfig({}); }, /must be configured/);
  assert.throws(function () {
    readConfig({
      CALL_API_PORT: "8080",
      LIVEKIT_PUBLIC_URL: "ws://calls.example.test",
      LIVEKIT_INTERNAL_URL: "http://127.0.0.1:7880",
      LIVEKIT_API_KEY: "key",
      LIVEKIT_API_SECRET: "secret"
    });
  }, /must use wss/);
});
