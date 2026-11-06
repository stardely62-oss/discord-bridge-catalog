// Finds leaked private keys that generic scanners miss: any 32-byte base64
// value in the tracked files or anywhere in the Git history that is the
// Ed25519 seed of a pinned public key (Flowseal manifests, catalog). Also
// rejects PEM private key blocks. Reports the file and key id only — never
// the value.
//
//   node scripts/ci/check-private-keys.mjs [--history]
//
// .github/secret-scan-allowlist.json lists blobs (full SHA) that were
// reviewed and contain no secret, with the reason — e.g. a test file that
// contained a literal PEM marker. Allowlisting is per exact blob: any change
// of the file is scanned again.
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const B64_32 = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])/g;
const PEM = /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/;

const blobSha = (buf) => createHash("sha1").update(`blob ${buf.length}\0`).update(buf).digest("hex");

export function publicOfSeed(seed) {
  const k = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
  return createPublicKey(k).export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
}

/** Pinned public keys: keys/*.b64 and every 44-char base64 in *_KEYS constants. */
export function pinnedKeys(root = ".") {
  const keys = new Set();
  const dir = path.join(root, "keys");
  if (fs.existsSync(dir)) for (const f of fs.readdirSync(dir)) if (f.endsWith(".b64")) keys.add(fs.readFileSync(path.join(dir, f), "utf8").trim());
  const rs = execFileSync("git", ["ls-files", "*.rs"], { cwd: root, encoding: "utf8" }).split("\n").filter(Boolean);
  for (const f of rs) {
    const src = fs.readFileSync(path.join(root, f), "utf8");
    for (const m of src.matchAll(/_KEYS:\s*&\[&str\]\s*=\s*&\[([^\]]*)\]/g)) for (const k of m[1].matchAll(/"([A-Za-z0-9+/]{43}=)"/g)) keys.add(k[1]);
  }
  return keys;
}

/** Findings in one text: [{reason, keyId}] without the secret value. */
export function scanText(text, pinned) {
  const out = [];
  if (PEM.test(text)) out.push({ reason: "PEM private key block" });
  for (const m of text.matchAll(B64_32)) {
    const raw = Buffer.from(m[0], "base64");
    if (raw.length !== 32 || pinned.has(m[0])) continue;
    let pub;
    try {
      pub = publicOfSeed(raw);
    } catch {
      continue;
    }
    if (pinned.has(pub)) out.push({ reason: "private seed of a pinned signing key", keyId: Buffer.from(pub, "base64").subarray(0, 8).toString("hex") });
  }
  return out;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const history = process.argv.includes("--history");
  const pinned = pinnedKeys();
  const git = (...a) => execFileSync("git", a, { encoding: "utf8", maxBuffer: 256 << 20 });
  const blobs = new Map();
  for (const f of git("ls-files", "-z").split("\0").filter(Boolean)) if (fs.existsSync(f)) blobs.set(`worktree:${f}`, () => fs.readFileSync(f));
  if (history) {
    // Every blob reachable from any ref, read in one batch (trees skipped).
    const list = execFileSync("git", ["cat-file", "--batch-check=%(objecttype) %(objectname) %(objectsize) %(rest)"], {
      input: git("rev-list", "--objects", "--all"),
      encoding: "utf8",
      maxBuffer: 256 << 20,
    });
    const want = [];
    for (const line of list.split("\n")) {
      const [type, sha, size, ...rest] = line.split(" ");
      if (type === "blob" && Number(size) <= 16 << 20) want.push({ sha, name: rest.join(" ") });
    }
    const out = execFileSync("git", ["cat-file", "--batch"], { input: want.map((w) => w.sha).join("\n") + "\n", maxBuffer: 1 << 30 });
    let pos = 0;
    for (const w of want) {
      const nl = out.indexOf(10, pos);
      const size = Number(out.subarray(pos, nl).toString().split(" ")[2]);
      const body = out.subarray(nl + 1, nl + 1 + size);
      pos = nl + 1 + size + 1;
      blobs.set(`${w.sha.slice(0, 7)}:${w.name}`, () => body);
    }
  }
  const allowFile = ".github/secret-scan-allowlist.json";
  const allowed = new Set(fs.existsSync(allowFile) ? JSON.parse(fs.readFileSync(allowFile, "utf8")).blobs.map((b) => b.sha) : []);
  let bad = 0;
  for (const [where, read] of blobs) {
    const buf = read();
    if (buf.length > 16 << 20) continue;
    if (allowed.size && allowed.has(blobSha(buf))) continue;
    for (const f of scanText(buf.toString("latin1"), pinned)) {
      bad++;
      console.error(`LEAK ${where}: ${f.reason}${f.keyId ? ` (key id ${f.keyId})` : ""}`);
    }
  }
  if (bad) process.exit(1);
  console.log(`ok: no private key of ${pinned.size} pinned public key(s) in ${blobs.size} files${history ? " (working tree and full history)" : ""}`);
}
