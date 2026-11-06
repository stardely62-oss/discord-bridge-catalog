// Signs dist/catalog-manifest.json into dist/catalog.signed.json with the
// Ed25519 seed from CATALOG_SIGNING_KEY (base64, 32 bytes) and refuses to
// sign unless that key matches the public key pinned in keys/ (the one the
// app trusts). The envelope format is the one bridge_core verifies.
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const dist = path.resolve(process.argv[2] ?? "dist");
const seedB64 = process.env.CATALOG_SIGNING_KEY;
if (!seedB64) { console.error("CATALOG_SIGNING_KEY is not set: refusing to publish an unsigned catalog"); process.exit(1); }
const seed = Buffer.from(seedB64.trim(), "base64");
if (seed.length !== 32) { console.error("CATALOG_SIGNING_KEY must be a base64 32-byte Ed25519 seed"); process.exit(1); }
const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
const pub = createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32);
const pinned = Buffer.from(fs.readFileSync(path.join(root, "keys/catalog-public-key.b64"), "utf8").trim(), "base64");
if (!pub.equals(pinned)) { console.error("the signing key does not match keys/catalog-public-key.b64"); process.exit(1); }
const bytes = fs.readFileSync(path.join(dist, "catalog-manifest.json"));
const signature = sign(null, bytes, key);
const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pinned]);
if (!verify(null, bytes, createPublicKey({ key: spki, format: "der", type: "spki" }), signature)) { console.error("self-check failed"); process.exit(1); }
const envelope = { manifest: bytes.toString("base64"), signature: signature.toString("base64"), keyId: pub.subarray(0, 8).toString("hex") };
fs.writeFileSync(path.join(dist, "catalog.signed.json"), JSON.stringify(envelope));
console.log(`signed with key ${envelope.keyId}`);
