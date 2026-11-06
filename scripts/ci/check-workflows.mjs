// Security policy for GitHub Actions workflows (shared by discord-bridge and
// discord-bridge-catalog). Fails CI when a workflow
//  1. uses an action by a movable ref (tag/branch) instead of a 40-hex SHA,
//     or without a "# version" comment next to the pin;
//  2. grants write permissions at the workflow level, or in a job that is
//     not on the policy's list of publish jobs;
//  3. lets a publish job build or run project code / third-party actions;
//  4. uses pull_request_target or workflow_run;
//  5. reads a secret (other than the job's own GITHUB_TOKEN) outside the
//     policy's signing jobs, or a signing job is reachable without its
//     protected environment / from a non-dispatch trigger / runs anything
//     but the dependency-free signer, or uploads anything but signed files;
//  6. keeps the token in .git/config after checkout;
//  7. interpolates attacker-controlled event fields into a shell.
//
//   node scripts/ci/check-workflows.mjs [--policy .github/workflow-policy.json] [--dir .github/workflows]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const SHA_REF = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40}$/;
const BUILD_CMD = /(^|[\s;&|(])(cargo|pnpm|npm|npx|yarn|pip3?|python3?|make|bash\s+\S+\.sh|\.\/\S+)(\s|$)/m;
const UNTRUSTED = /\$\{\{\s*github\.(head_ref|event\.(pull_request\.(title|body|head\.ref|head\.label)|issue\.(title|body)|comment\.body|review\.body|commits|head_commit\.message))/;

const asArray = (v) => (Array.isArray(v) ? v : v == null ? [] : [v]);
const triggers = (on) => (typeof on === "string" ? [on] : Array.isArray(on) ? on : Object.keys(on ?? {}));
const grantsWrite = (perm) => {
  if (perm == null) return false;
  if (typeof perm === "string") return perm === "write-all";
  return Object.values(perm).some((v) => v === "write");
};
const secretsIn = (text) => [...String(text).matchAll(/secrets\.([A-Za-z0-9_]+)/g)].map((m) => m[1]).filter((s) => s !== "GITHUB_TOKEN");

/** Returns a list of human-readable violations (empty = compliant). */
export function checkWorkflow(file, text, policy) {
  const errors = [];
  const err = (where, msg) => errors.push(`${file}${where ? ` [${where}]` : ""}: ${msg}`);
  const wf = yaml.load(text);
  const on = triggers(wf.on ?? wf.true);
  const writeJobs = policy.writeJobs?.[file] ?? [];
  const signJobs = policy.signingJobs?.[file] ?? {};

  // 1. Pinned actions (raw text, to see the version comment).
  text.split("\n").forEach((line, i) => {
    const m = line.match(/^\s*(?:-\s*)?uses:\s*([^\s#]+)\s*(#.*)?$/);
    if (!m || m[1].startsWith("./") || m[1].startsWith("docker://")) return;
    if (!SHA_REF.test(m[1])) err(`line ${i + 1}`, `action "${m[1]}" is not pinned to a full commit SHA`);
    else if (!m[2] || !/#\s*\S/.test(m[2])) err(`line ${i + 1}`, `pinned action "${m[1].split("@")[0]}" has no "# version" comment`);
  });

  // 4. Dangerous triggers.
  for (const t of ["pull_request_target", "workflow_run"]) if (on.includes(t)) err("on", `trigger ${t} is not allowed`);

  // 2. Workflow-level permissions: explicit and read-only.
  if (wf.permissions === undefined) err("permissions", "workflow must declare permissions explicitly");
  else if (grantsWrite(wf.permissions)) err("permissions", "write permissions are granted per job, never workflow-wide");

  for (const [id, job] of Object.entries(wf.jobs ?? {})) {
    const steps = asArray(job.steps);
    const where = `job ${id}`;
    const jobText = yaml.dump(job);

    // 6. Checkout never persists credentials.
    steps.forEach((s, i) => {
      if (String(s.uses ?? "").startsWith("actions/checkout@") && s.with?.["persist-credentials"] !== false) err(`${where} step ${i + 1}`, "actions/checkout must set persist-credentials: false");
    });

    // 7. No attacker-controlled event fields in shells.
    steps.forEach((s, i) => {
      if (s.run && UNTRUSTED.test(s.run)) err(`${where} step ${i + 1}`, "untrusted event field interpolated into run (pass it through env)");
    });

    // 2/3. Write access only in listed publish jobs, which build nothing.
    if (grantsWrite(job.permissions)) {
      if (!writeJobs.includes(id)) err(where, "grants write permissions but is not a policy publish job");
      steps.forEach((s, i) => {
        if (s.uses && !String(s.uses).startsWith("actions/download-artifact@")) err(`${where} step ${i + 1}`, `publish job may only download artifacts, not use ${String(s.uses).split("@")[0]}`);
        if (s.run && BUILD_CMD.test(s.run)) err(`${where} step ${i + 1}`, "publish job must not build or run project code");
      });
      if (secretsIn(jobText).length) err(where, "publish job must not read secrets");
    } else if (writeJobs.includes(id) && job.permissions === undefined) {
      err(where, "publish job must declare its permissions");
    }

    // 5. Secrets only in signing jobs, under strict conditions.
    const secrets = secretsIn(jobText);
    const rule = signJobs[id];
    if (secrets.length && !rule) err(where, `reads secrets (${[...new Set(secrets)].join(", ")}) but is not a policy signing job`);
    if (rule) {
      const extra = secrets.filter((s) => !rule.secrets.includes(s));
      if (extra.length) err(where, `reads unexpected secrets ${extra.join(", ")}`);
      if (job.environment !== rule.environment && job.environment?.name !== rule.environment) err(where, `signing job must run in the protected environment ${rule.environment}`);
      if (!/github\.ref\s*==\s*'refs\/heads\/main'/.test(String(job.if ?? ""))) err(where, "signing job must be limited to refs/heads/main");
      if (on.some((t) => t !== "workflow_dispatch")) err(where, "a workflow with a signing job may only be triggered by workflow_dispatch");
      if (grantsWrite(job.permissions)) err(where, "signing job must not have write permissions");
      steps.forEach((s, i) => {
        const u = String(s.uses ?? "").split("@")[0];
        if (s.uses && !["actions/checkout", "actions/download-artifact", "actions/upload-artifact"].includes(u)) err(`${where} step ${i + 1}`, `signing job may not use ${u}`);
        if (u === "actions/upload-artifact" && !asArray(String(s.with?.path ?? "").split("\n").filter(Boolean)).every((p) => /\.signed\.json$/.test(p.trim()))) err(`${where} step ${i + 1}`, "signing job may upload only *.signed.json");
        if (s.run && !rule.signer.some((cmd) => s.run.trim().startsWith(cmd))) err(`${where} step ${i + 1}`, "signing job may run only the dependency-free signer");
        const stepSecrets = secretsIn(yaml.dump(s));
        if (stepSecrets.length) {
          if (!s.run || !rule.signer.some((cmd) => s.run.trim().startsWith(cmd))) err(`${where} step ${i + 1}`, "a secret may reach only the signer command");
          if (secretsIn(s.run ?? "").length || secretsIn(yaml.dump(s.with ?? {})).length) err(`${where} step ${i + 1}`, "secrets are passed only through env");
        }
      });
      if (secretsIn(yaml.dump(job.env ?? {})).length) err(where, "secrets must be scoped to the signing step, not the job");
    }
  }
  if (secretsIn(yaml.dump(wf.env ?? {})).length) err("env", "secrets must not be exposed workflow-wide");
  return errors;
}

export function checkAll(dir, policy) {
  const files = fs.readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).sort();
  const errors = files.flatMap((f) => checkWorkflow(f, fs.readFileSync(path.join(dir, f), "utf8"), policy));
  for (const f of [...Object.keys(policy.writeJobs ?? {}), ...Object.keys(policy.signingJobs ?? {})]) if (!files.includes(f)) errors.push(`policy names ${f}, which does not exist`);
  return { files, errors };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opt = (k, d) => (args.includes(k) ? args[args.indexOf(k) + 1] : d);
  const policy = JSON.parse(fs.readFileSync(opt("--policy", ".github/workflow-policy.json"), "utf8"));
  const { files, errors } = checkAll(opt("--dir", ".github/workflows"), policy);
  if (errors.length) {
    for (const e of errors) console.error(`policy: ${e}`);
    process.exit(1);
  }
  console.log(`ok: ${files.length} workflows follow the security policy (${files.join(", ")})`);
}
