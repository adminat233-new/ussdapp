import test from "node:test";
import assert from "node:assert/strict";
import { parseInvitation, createInvitation } from "./invitation.js";

test("creates and parses the invitation format used by Android", function () {
  const key = Uint8Array.from({ length: 32 }, function (_, index) { return index; });
  const invitation = createInvitation("a".repeat(48), key);
  const parsed = parseInvitation(invitation);

  assert.equal(parsed.code, "a".repeat(48));
  assert.equal(parsed.key.length, 43);
});

test("rejects malformed or truncated invitations", function () {
  assert.throws(function () { parseInvitation("not-an-invitation"); }, /format is invalid/);
  assert.throws(function () { parseInvitation("a".repeat(48) + ":" + "A".repeat(42)); }, /format is invalid/);
  assert.throws(function () { createInvitation("z".repeat(48), new Uint8Array(32)); }, /valid private invitation/);
});
