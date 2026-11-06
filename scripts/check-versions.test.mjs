// node --test scripts/ — offline, deterministic.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import { compare, currentPacks, normIps, verifyPublished } from "./check-versions.mjs";

const p = (version, domains, ips = []) => ({ id: "steam", version, domains, ips });

test("same addresses in another order and case are not a change", () => {
  assert.deepEqual(compare([p(1, ["a.com", "B.com"], ["1.1.1.0/24"])], [p(1, ["b.com", "a.com"], ["1.1.1.7/24"])], "x"), []);
  assert.deepEqual(normIps(["2001:db8::/32", "2001:0db8:0::/32"]).length, 1);
});

test("changed domains or IPs at the same version fail", () => {
  assert.equal(compare([p(1, ["a.com"])], [p(1, ["a.com", "evil.com"])], "x").length, 1);
  assert.equal(compare([p(2, ["a.com"], ["1.1.1.0/24"])], [p(2, ["a.com"], ["1.1.2.0/24"])], "x").length, 1);
});

test("a lower version fails, a higher one passes", () => {
  assert.match(compare([p(3, ["a.com"])], [p(2, ["a.com"])], "x")[0], /lower/);
  assert.deepEqual(compare([p(1, ["a.com"])], [p(2, ["b.com"])], "x"), []);
});

test("metadata-only changes, new and removed packs are allowed", () => {
  const a = { ...p(1, ["a.com"]), description: { ru: "1", en: "1" } };
  const b = { ...p(1, ["a.com"]), description: { ru: "2", en: "2" } };
  assert.deepEqual(compare([a], [b], "x"), []);
  assert.deepEqual(compare([], [a], "x"), []);
  assert.deepEqual(compare([a], [], "x"), []);
});

test("the published baseline must verify with the pinned key", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
  const data = Buffer.from(JSON.stringify({ format: 1, serial: 5, packs: [p(1, ["a.com"])], icons: [] }));
  const manifest = Buffer.from(JSON.stringify({ kind: "discord-bridge-catalog", serial: 5, data: { size: data.length, sha256: createHash("sha256").update(data).digest("hex") } }));
  const signed = Buffer.from(JSON.stringify({ manifest: manifest.toString("base64"), signature: sign(null, manifest, privateKey).toString("base64"), keyId: "x" }));
  assert.equal(verifyPublished(signed, data, [pub]).packs[0].id, "steam");
  const other = generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
  assert.throws(() => verifyPublished(signed, data, [other]), /signature/);
  assert.throws(() => verifyPublished(signed, Buffer.concat([data, Buffer.from(" ")]), [pub]), /SHA-256/);
});

test("the packs in this repository are valid input", () => {
  const cur = currentPacks();
  assert.ok(cur.length > 0, "expected at least one maintained catalog pack");
  assert.deepEqual(compare(cur, cur, "self"), []);
});
