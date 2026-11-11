// Validates packs/ and icons/ and builds a deterministic snapshot:
//   node scripts/build.mjs [--out dist] [--serial N]
// Writes <out>/catalog-data.json and <out>/catalog-manifest.json (unsigned).
// The serial defaults to the commit time of HEAD (monotonic on main), so the
// same commit always produces the same bytes. No dependencies.
// The rules mirror bridge_core::packs (the app re-validates everything).
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { parseNet } from "./lib/net.mjs";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const args = process.argv.slice(2);
const opt = (k, d) => (args.includes(k) ? args[args.indexOf(k) + 1] : d);
const out = path.resolve(opt("--out", "dist"));

const LIMITS = { packs: 500, domains: 2000, ips: 5000, icons: 600, iconBytes: 64 * 1024, iconSide: 512, data: 4 * 1024 * 1024, text: 600, name: 60 };
const CATEGORIES = ["messenger", "voice", "game", "launcher", "video", "streaming", "service", "other"];
const SOURCES = ["official", "community"];
const PROV = ["domains", "ips", "icon"];
const FLOWSEAL = ["list-general.txt", "list-google.txt"];
const KEYS = ["schema", "id", "version", "updated", "name", "description", "category", "source", "icon", "domains", "ips", "provenance", "notes", "partialCoverage", "requires", "ports", "flowsealList", "minAppVersion"];
const MAX_PORT_ITEMS = 32;

const errors = [];
const fail = (where, msg) => errors.push(`${where}: ${msg}`);
const sha = (b) => createHash("sha256").update(b).digest("hex");
const idOk = (s) => typeof s === "string" && /^[a-z0-9][a-z0-9-]{0,39}$/.test(s);
const textOk = (s, max) => typeof s === "string" && s.trim() !== "" && [...s].length <= max && !/[\u0000-\u001f\u007f]/.test(s);
const localized = (v, max) => v && typeof v === "object" && Object.keys(v).sort().join() === "en,ru" && textOk(v.ru, max) && textOk(v.en, max);
const domainOk = (d) => typeof d === "string" && d.length <= 253 && d.replace(/^\^/, "").split(".").every((l) => l.length > 0 && l.length <= 63 && /^[A-Za-z0-9_-]+$/.test(l));
// `ports.tcp` / `ports.udp`: "5055-5058", "443,4530" — the syntax of
// --filter-tcp/--filter-udp without game-filter variables (bridge_core::packs::PackPorts).
const portsError = (ports) => {
  if (!ports || typeof ports !== "object" || Array.isArray(ports)) return "ports must be an object";
  const keys = Object.keys(ports);
  if (!keys.length || keys.some((k) => k !== "tcp" && k !== "udp")) return "ports may only have tcp and/or udp";
  for (const k of keys) {
    const v = ports[k];
    if (typeof v !== "string" || !/^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$/.test(v)) return `ports.${k}: use "443" or "5055-5058", comma separated, no spaces`;
    const items = v.split(",");
    if (items.length > MAX_PORT_ITEMS) return `ports.${k}: more than ${MAX_PORT_ITEMS} items`;
    for (const it of items) {
      const [a, b = a] = it.split("-").map(Number);
      if (a < 1 || b > 65535 || a > b) return `ports.${k}: "${it}" is not a port or range 1-65535`;
    }
  }
  return null;
};
const urlOk = (u) => {
  if (typeof u !== "string" || !u.startsWith("https://") || u.length > 300 || /[\s\\\u0000-\u001f]/.test(u)) return false;
  const host = u.slice(8).split("/")[0];
  return host.includes(".") && !host.includes("@");
};


function imageSize(b) {
  if (b.length >= 24 && b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) && b.subarray(12, 16).toString() === "IHDR")
    return ["png", b.readUInt32BE(16), b.readUInt32BE(20)];
  if (b.length >= 30 && b.subarray(0, 4).toString() === "RIFF" && b.subarray(8, 12).toString() === "WEBP") {
    const k = b.subarray(12, 16).toString();
    if (k === "VP8X") return ["webp", b.readUIntLE(24, 3) + 1, b.readUIntLE(27, 3) + 1];
    if (k === "VP8L" && b[20] === 0x2f) { const v = b.readUInt32LE(21); return ["webp", (v & 0x3fff) + 1, ((v >>> 14) & 0x3fff) + 1]; }
    if (k === "VP8 ") return ["webp", b.readUInt16LE(26) & 0x3fff, b.readUInt16LE(28) & 0x3fff];
  }
  return null;
}

// Icons
const iconDir = path.join(root, "icons");
const icons = [];
for (const name of fs.readdirSync(iconDir).filter((n) => !n.endsWith(".md")).sort()) {
  const where = `icons/${name}`;
  const m = /^([a-z0-9][a-z0-9-]{0,39})\.(png|webp)$/.exec(name);
  if (!m) { fail(where, "only [a-z0-9-].png / .webp files are allowed (no SVG)"); continue; }
  const b = fs.readFileSync(path.join(iconDir, name));
  if (b.length > LIMITS.iconBytes) fail(where, `larger than ${LIMITS.iconBytes} bytes`);
  const size = imageSize(b);
  if (!size || size[0] !== m[2]) { fail(where, "not a valid PNG/WebP matching its extension"); continue; }
  if (!size[1] || !size[2] || size[1] > LIMITS.iconSide || size[2] > LIMITS.iconSide) fail(where, `size ${size[1]}x${size[2]}`);
  icons.push({ name, sha256: sha(b), data: b.toString("base64") });
}
const iconNames = new Set(icons.map((i) => i.name));

// Packs
const packDir = path.join(root, "packs");
const packs = [];
const ids = new Set();
for (const file of fs.readdirSync(packDir).sort()) {
  const where = `packs/${file}`;
  if (!file.endsWith(".json")) { fail(where, "only .json files"); continue; }
  let p;
  try { p = JSON.parse(fs.readFileSync(path.join(packDir, file), "utf8")); } catch (e) { fail(where, `invalid JSON: ${e.message}`); continue; }
  for (const k of Object.keys(p)) if (!KEYS.includes(k)) fail(where, `unknown field "${k}"`);
  if (p.schema !== 1) fail(where, "schema must be 1");
  if (!idOk(p.id) || file !== `${p.id}.json`) fail(where, "id must be [a-z0-9-] and match the file name");
  if (ids.has(p.id)) fail(where, "duplicate id");
  ids.add(p.id);
  if (!Number.isInteger(p.version) || p.version < 1) fail(where, "version must be an integer >= 1");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(p.updated ?? "")) fail(where, "updated must be YYYY-MM-DD");
  if (!localized(p.name, LIMITS.name)) fail(where, "name {ru,en} required");
  if (!localized(p.description, LIMITS.text)) fail(where, "description {ru,en} required");
  if (p.notes !== undefined && !localized(p.notes, LIMITS.text)) fail(where, "notes must be {ru,en}");
  if (!CATEGORIES.includes(p.category)) fail(where, `category must be one of ${CATEGORIES}`);
  if (!SOURCES.includes(p.source)) fail(where, `source must be one of ${SOURCES}`);
  if (p.icon !== undefined && !iconNames.has(p.icon)) fail(where, `icon ${p.icon} not found in icons/`);
  if (p.flowsealList !== undefined && !FLOWSEAL.includes(p.flowsealList)) fail(where, "unknown flowsealList");
  if (p.minAppVersion !== undefined && !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(p.minAppVersion)) fail(where, "minAppVersion must be SemVer");
  if (p.ports !== undefined) {
    const e = portsError(p.ports);
    if (e) fail(where, e);
  }
  const domains = p.domains ?? [], ips = p.ips ?? [];
  if (!Array.isArray(domains) || !Array.isArray(ips)) fail(where, "domains/ips must be arrays");
  if (!domains.length && !ips.length) fail(where, "no domains and no IPs");
  if (domains.length > LIMITS.domains || ips.length > LIMITS.ips) fail(where, "too many entries");
  const seenD = new Set();
  for (const d of domains) {
    if (!domainOk(d) || d !== d.trim()) fail(where, `"${d}" is not a domain`);
    if (seenD.has(String(d).toLowerCase())) fail(where, `duplicate domain ${d}`);
    seenD.add(String(d).toLowerCase());
  }
  const seenN = new Set();
  for (const ip of ips) {
    const n = parseNet(ip);
    if (!n) { fail(where, `"${ip}" is not an IP or CIDR`); continue; }
    if (n.prefix < (n.v6 ? 16 : 8)) fail(where, `"${ip}" is too wide`);
    const key = `${n.v6}/${n.bits}/${n.prefix}`;
    if (seenN.has(key)) fail(where, `duplicate network ${ip}`);
    seenN.add(key);
  }
  for (const pr of p.provenance ?? []) {
    if (!PROV.includes(pr.kind) || !urlOk(pr.url)) fail(where, "provenance needs kind and an https url");
    if (pr.note !== undefined && !textOk(pr.note, LIMITS.text)) fail(where, "provenance note invalid");
  }
  if (ips.length && !(p.provenance ?? []).some((x) => x.kind === "ips")) fail(where, "IPs need an 'ips' provenance entry");
  packs.push(p);
}
if (packs.length > LIMITS.packs || icons.length > LIMITS.icons) fail("catalog", "too many packs or icons");

if (errors.length) {
  console.error(errors.map((e) => `ERROR ${e}`).join("\n"));
  process.exit(1);
}

const serial = Number(args.includes("--serial") ? opt("--serial") : execFileSync("git", ["log", "-1", "--format=%ct"], { cwd: root }).toString().trim());
if (!Number.isSafeInteger(serial) || serial <= 0) { console.error("ERROR serial must be a positive integer"); process.exit(1); }
const published = new Date(serial * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const data = Buffer.from(JSON.stringify({ format: 1, serial, packs, icons }));
if (data.length > LIMITS.data) { console.error("ERROR catalog data larger than 4 MiB"); process.exit(1); }
const manifest = {
  kind: "discord-bridge-catalog",
  format: 1,
  serial,
  published,
  packSchema: 1,
  data: { name: "catalog-data.json", sha256: sha(data), size: data.length },
  packs: packs.length,
  icons: icons.length,
};
fs.mkdirSync(out, { recursive: true });
fs.writeFileSync(path.join(out, "catalog-data.json"), data);
fs.writeFileSync(path.join(out, "catalog-manifest.json"), JSON.stringify(manifest));
console.log(`ok: ${packs.length} packs, ${icons.length} icons, serial ${serial}, data ${data.length} bytes, sha256 ${manifest.data.sha256}`);
