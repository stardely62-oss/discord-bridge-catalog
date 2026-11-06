// Verifies a signed catalog before publication, with the pinned public key
// only: signature, kind, data size and SHA-256, serial. No key, no deps.
//   node scripts/verify-signed.mjs <dir-with-catalog.signed.json-and-catalog-data.json> [--expect-manifest-sha256 <hex>]
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyPublished } from "./check-versions.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const dir = path.resolve(args[0] ?? "dist");
const expect = args.includes("--expect-manifest-sha256") ? args[args.indexOf("--expect-manifest-sha256") + 1] : undefined;
try {
  const signed = fs.readFileSync(path.join(dir, "catalog.signed.json"));
  const data = fs.readFileSync(path.join(dir, "catalog-data.json"));
  const pinned = fs.readFileSync(path.join(root, "keys/catalog-public-key.b64"), "utf8").trim();
  const env = JSON.parse(signed.toString("utf8"));
  if (Object.keys(env).sort().join() !== "keyId,manifest,signature") throw new Error("unexpected fields in the envelope");
  const manifestBytes = Buffer.from(env.manifest, "base64");
  if (expect && createHash("sha256").update(manifestBytes).digest("hex") !== expect) throw new Error("signed manifest is not the one the build job produced");
  const d = verifyPublished(signed, data, [pinned]);
  console.log(`ok: catalog ${d.serial}, ${d.packs.length} packs, ${d.icons.length} icons — signature (pinned key), data size and SHA-256 verified`);
} catch (e) {
  console.error(`verify: ${e.message}`);
  process.exit(1);
}
