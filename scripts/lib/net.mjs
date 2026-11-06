// IPv4 / IPv6 address or CIDR parser shared by the build and the version
// check. Host bits are masked, so "1.2.3.4/24" and "1.2.3.0/24" are equal.
export function parseNet(s) {
  if (typeof s !== "string") return null;
  const [ip, mask, extra] = s.split("/");
  if (extra !== undefined) return null;
  let v6 = false, bits = 0n, width = 32;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    const parts = ip.split(".").map(Number);
    if (parts.some((p) => p > 255)) return null;
    bits = parts.reduce((a, p) => (a << 8n) | BigInt(p), 0n);
  } else if (ip.includes(":")) {
    v6 = true; width = 128;
    const [head, tail, more] = ip.split("::");
    if (more !== undefined) return null;
    const h = head ? head.split(":") : [];
    const t = tail !== undefined ? (tail ? tail.split(":") : []) : null;
    const groups = t === null ? h : [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
    if (groups.length !== 8 || groups.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return null;
    bits = groups.reduce((a, g) => (a << 16n) | BigInt(parseInt(g, 16)), 0n);
  } else return null;
  let prefix = width;
  if (mask !== undefined) {
    if (!/^\d+$/.test(mask) || Number(mask) > width) return null;
    prefix = Number(mask);
  }
  const m = prefix === 0 ? 0n : (((1n << BigInt(width)) - 1n) >> BigInt(width - prefix)) << BigInt(width - prefix);
  return { v6, bits: bits & m, prefix };
}

/** Canonical, order-independent key of one network. */
export const netKey = (n) => `${n.v6 ? 6 : 4}/${n.bits.toString(16)}/${n.prefix}`;
