// Signs <dist>/catalog-manifest.json into <dist>/catalog.signed.json with the
// Ed25519 seed from CATALOG_SIGNING_KEY (base64, 32 bytes). Dependency-free
// (Node's built-in crypto only), so the signing job of the publish workflow
// runs no package manager, no build and no third-party action next to the key.
//
//   node scripts/sign.mjs <dist> [--expect-sha256 <hex>]
//
// Refuses to sign unless
// - the manifest's SHA-256 is the one the build job reported (job output,
//   not the artifact store), when --expect-sha256 is given;
// - the manifest is a discord-bridge-catalog manifest;
// - the key derives to the public key pinned in keys/ (the one the app trusts).
// Verifies its own signature with the pinned key. The key is read from the
// environment once, removed from it and never written anywhere. The envelope
// format is the one bridge_core verifies.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const die = (msg) => {
  console.error(msg);
  process.exit(1);
};
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const dist = path.resolve(args.find((a, i) => !a.startsWith("--") && args[i - 1] !== "--expect-sha256") ?? "dist");
const expect = args.includes("--expect-sha256") ? args[args.indexOf("--expect-sha256") + 1] : undefined;

const bytes = fs.readFileSync(path.join(dist, "catalog-manifest.json"));
const got = createHash("sha256").update(bytes).digest("hex");
if (expect !== undefined && (!/^[0-9a-f]{64}$/.test(expect) || got !== expect)) die(`manifest SHA-256 ${got} is not the one the build job produced`);
let m;
try {
  m = JSON.parse(bytes.toString("utf8"));
} catch {
  die("catalog-manifest.json is not JSON");
}
if (m.kind !== "discord-bridge-catalog") die("not a discord-bridge-catalog manifest");

const pinned = Buffer.from(fs.readFileSync(path.join(root, "keys/catalog-public-key.b64"), "utf8").trim(), "base64");
const seedB64 = process.env.CATALOG_SIGNING_KEY;
delete process.env.CATALOG_SIGNING_KEY;
if (!seedB64) die("CATALOG_SIGNING_KEY is not set: refusing to publish an unsigned catalog");
const seed = Buffer.from(seedB64.trim(), "base64");
if (seed.length !== 32) die("CATALOG_SIGNING_KEY must be a base64 32-byte Ed25519 seed");
const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
seed.fill(0);
const pub = createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32);
if (!pub.equals(pinned)) die("the signing key does not match keys/catalog-public-key.b64");
const signature = sign(null, bytes, key);
const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pinned]);
if (!verify(null, bytes, createPublicKey({ key: spki, format: "der", type: "spki" }), signature)) die("self-check failed");
const envelope = { manifest: bytes.toString("base64"), signature: signature.toString("base64"), keyId: pub.subarray(0, 8).toString("hex") };
fs.writeFileSync(path.join(dist, "catalog.signed.json"), JSON.stringify(envelope));
console.log(`signed catalog ${m.serial} (manifest sha256 ${got}) with key ${envelope.keyId}`);
