// Pack versioning rule: if a pack's domains or IPs change, its `version`
// must grow; a version never goes down. Addresses are compared normalized
// (case, order, duplicates and CIDR host bits do not matter). Metadata and
// icons may change without a new version (the app binds every install to
// the exact SHA-256 of the pack anyway).
//
//   node scripts/check-versions.mjs [--base <git-ref>] [--published] [--published-dir <dir>]
//
// --base           compare with packs/*.json of a git ref (PR base, previous push)
// --published      compare with the latest published release, downloaded from
//                  GitHub and verified (Ed25519 signature with the pinned key,
//                  size and SHA-256 of the data) — so rewriting history cannot
//                  bypass the rule
// --published-dir  the same from local catalog.signed.json + catalog-data.json
// Without the release (nothing published yet) --published fails unless
// --allow-unpublished is given.
import { createHash, createPublicKey, verify } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { netKey, parseNet } from "./lib/net.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export const normDomains = (v = []) => [...new Set(v.map((d) => String(d).trim().toLowerCase()).filter(Boolean))].sort();
export const normIps = (v = []) => [...new Set(v.map((s) => { const n = parseNet(s); return n ? netKey(n) : `invalid:${s}`; }))].sort();
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Violations of the rule between a baseline and the current packs. */
export function compare(baseline, current, label) {
  const errors = [];
  const base = new Map(baseline.map((p) => [p.id, p]));
  for (const p of current) {
    const b = base.get(p.id);
    if (!b) continue;
    const changed = !same(normDomains(b.domains), normDomains(p.domains)) || !same(normIps(b.ips), normIps(p.ips));
    if (p.version < b.version) errors.push(`${p.id}: version ${p.version} is lower than ${b.version} in ${label}`);
    else if (p.version === b.version && changed) errors.push(`${p.id}: domains or IPs changed but version stays ${p.version} (${label}) — increase "version"`);
  }
  return errors;
}

export function currentPacks(dir = path.join(root, "packs")) {
  return fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort().map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")));
}

export function packsAtRef(ref) {
  const git = (...a) => execFileSync("git", a, { cwd: root, encoding: "utf8", maxBuffer: 64 << 20 });
  const files = git("ls-tree", "--name-only", `${ref}:packs`).split("\n").filter((f) => f.endsWith(".json"));
  return files.map((f) => JSON.parse(git("show", `${ref}:packs/${f}`)));
}

/** Verified data of a published catalog: signature with one of `keys`
 * (base64 Ed25519), kind, size and SHA-256 of the data, same serial. */
export function verifyPublished(signedBytes, dataBytes, keys) {
  const env = JSON.parse(signedBytes.toString("utf8"));
  const manifestBytes = Buffer.from(env.manifest, "base64");
  const sig = Buffer.from(env.signature, "base64");
  const ok = keys.some((k) => {
    const raw = Buffer.from(k.trim(), "base64");
    if (raw.length !== 32) return false;
    const pub = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]), format: "der", type: "spki" });
    return verify(null, manifestBytes, pub, sig);
  });
  if (!ok) throw new Error("published catalog: signature does not verify with the pinned key");
  const m = JSON.parse(manifestBytes.toString("utf8"));
  if (m.kind !== "discord-bridge-catalog") throw new Error("published catalog: wrong kind");
  if (dataBytes.length !== m.data.size || createHash("sha256").update(dataBytes).digest("hex") !== m.data.sha256) throw new Error("published catalog: data size / SHA-256 mismatch");
  const data = JSON.parse(dataBytes.toString("utf8"));
  if (data.serial !== m.serial) throw new Error("published catalog: serial mismatch");
  return data;
}

export function trustedKeys() {
  const keys = [fs.readFileSync(path.join(root, "keys/catalog-public-key.b64"), "utf8").trim()];
  // During a key rotation the latest release is still signed by the old key.
  for (const k of (process.env.BASELINE_EXTRA_KEYS ?? "").split(",")) if (k.trim()) keys.push(k.trim());
  return keys;
}

async function download(url, limit) {
  const r = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(30_000) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  const b = Buffer.from(await r.arrayBuffer());
  if (b.length > limit) throw new Error(`${url}: too large`);
  return b;
}

async function publishedPacks(dir) {
  let signed, data;
  if (dir) {
    signed = fs.readFileSync(path.join(dir, "catalog.signed.json"));
    data = fs.readFileSync(path.join(dir, "catalog-data.json"));
  } else {
    const repo = process.env.GITHUB_REPOSITORY ?? "stardely62-oss/discord-bridge-catalog";
    signed = await download(`https://github.com/${repo}/releases/latest/download/catalog.signed.json`, 64 * 1024);
    if (!signed) return null;
    const serial = JSON.parse(Buffer.from(JSON.parse(signed).manifest, "base64")).serial;
    data = await download(`https://github.com/${repo}/releases/download/catalog-${serial}/catalog-data.json`, 4 << 20);
    if (!data) throw new Error(`release catalog-${serial} has no catalog-data.json`);
  }
  const d = verifyPublished(signed, data, trustedKeys());
  return { serial: d.serial, packs: d.packs };
}

async function main() {
  const args = process.argv.slice(2);
  const opt = (k) => (args.includes(k) ? args[args.indexOf(k) + 1] : undefined);
  const cur = currentPacks();
  const errors = [];
  const base = opt("--base");
  if (base) {
    errors.push(...compare(packsAtRef(base), cur, `git ${base}`));
    console.log(`compared with git ${base}`);
  }
  if (args.includes("--published") || opt("--published-dir")) {
    const pub = await publishedPacks(opt("--published-dir"));
    if (!pub) {
      if (!args.includes("--allow-unpublished")) errors.push("no published catalog found");
    } else {
      errors.push(...compare(pub.packs, cur, `published catalog-${pub.serial}`));
      console.log(`compared with published catalog-${pub.serial} (signature verified)`);
    }
  }
  if (errors.length) {
    for (const e of errors) console.error(`error: ${e}`);
    process.exit(1);
  }
  console.log(`ok: ${cur.length} packs follow the versioning rule`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { console.error(`error: ${e.message}`); process.exit(1); });
}
