import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import fs from "node:fs";
import { test } from "node:test";
import { pinnedKeys, publicOfSeed, scanText } from "./check-private-keys.mjs";

test("the pinned catalog key is found", () => {
  const k = pinnedKeys();
  assert.ok(k.has(fs.readFileSync("keys/catalog-public-key.b64", "utf8").trim()));
});

test("a seed of a pinned key is detected without printing it; public keys and other values are not", () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const pub = publicOfSeed(seed);
  const pinned = new Set([pub]);
  const seedB64 = seed.toString("base64");
  const found = scanText(`KEY=${seedB64}\n`, pinned);
  assert.equal(found.length, 1);
  assert.ok(!JSON.stringify(found).includes(seedB64));
  assert.deepEqual(scanText(`pub=${pub}\n`, pinned), []);
  assert.deepEqual(scanText(`x=${Buffer.alloc(32, 7).toString("base64")}\n`, pinned), []);
  const marker = ["-----BEGIN", "PRIVATE", "KEY-----"].join(" ");
  assert.equal(scanText(`${marker}\nAAAA\n`, pinned).length, 1);
});
