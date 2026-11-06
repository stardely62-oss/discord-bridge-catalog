// Every new commit (author, committer, Co-Authored-By) must use a GitHub
// noreply address (or GitHub's / Anthropic's own noreply). A personal
// address is reported masked (e***@g***.com), never in full.
//
//   node scripts/ci/check-commit-emails.mjs <base-sha> <head-sha>
//   node scripts/ci/check-commit-emails.mjs --last N
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ALLOWED = [
  /^\d+\+[A-Za-z0-9-]+@users\.noreply\.github\.com$/,
  /^[A-Za-z0-9-]+@users\.noreply\.github\.com$/,
  /^noreply@github\.com$/,
  /^noreply@anthropic\.com$/,
  /^\d+\+[A-Za-z0-9-]+\[bot\]@users\.noreply\.github\.com$/,
];

export const allowed = (email) => ALLOWED.some((r) => r.test(email.trim().toLowerCase()));

/** "someone@example.org" → "s***@e***.org" */
export function mask(email) {
  const [user, domain = ""] = email.trim().split("@");
  const parts = domain.split(".");
  const tld = parts.length > 1 ? `.${parts.pop()}` : "";
  return `${user.slice(0, 1)}***@${parts.join(".").slice(0, 1)}***${tld}`;
}

export function violations(commits) {
  const out = [];
  for (const c of commits) {
    const emails = [
      ["author", c.author],
      ["committer", c.committer],
      ...[...c.body.matchAll(/^Co-authored-by:.*<([^>]+)>\s*$/gim)].map((m) => ["co-author", m[1]]),
    ];
    for (const [role, e] of emails) if (!allowed(e)) out.push(`${c.sha.slice(0, 7)} ${role} ${mask(e)}`);
  }
  return out;
}

function commitsIn(range) {
  const SEP = "\u001e", F = "\u001f";
  const raw = execFileSync("git", ["log", `--format=%H${F}%ae${F}%ce${F}%B${SEP}`, ...range], { encoding: "utf8", maxBuffer: 64 << 20 });
  return raw.split(SEP).map((s) => s.replace(/^\n/, "")).filter(Boolean).map((r) => {
    const [sha, author, committer, body] = r.split(F);
    return { sha, author, committer, body };
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const a = process.argv.slice(2);
  const zero = /^0{40}$/;
  let range;
  if (a[0] === "--last") range = ["-n", a[1] ?? "1"];
  else if (a.length === 2 && a[0] && !zero.test(a[0])) range = [`${a[0]}..${a[1]}`];
  else range = ["-n", "1", a[1] ?? "HEAD"];
  const commits = commitsIn(range);
  const bad = violations(commits);
  if (bad.length) {
    console.error("Commits with a non-noreply email (masked):");
    for (const b of bad) console.error(`  ${b}`);
    console.error("Use your GitHub noreply address: git config user.email <id>+<login>@users.noreply.github.com — see docs/release-security.md.");
    process.exit(1);
  }
  console.log(`ok: ${commits.length} commit(s) use noreply addresses only`);
}
