import assert from "node:assert/strict";
import { test } from "node:test";
import { allowed, mask, violations } from "./check-commit-emails.mjs";

test("noreply addresses are allowed, personal ones are not", () => {
  assert.ok(allowed("268722850+stardely62-oss@users.noreply.github.com"));
  assert.ok(allowed("noreply@github.com"));
  assert.ok(allowed("noreply@anthropic.com"));
  assert.ok(!allowed("someone@gmail.com"));
  assert.ok(!allowed("x@users.noreply.github.com.evil.example"));
});

test("reports are masked", () => {
  assert.equal(mask("someone@gmail.com"), "s***@g***.com");
  const v = violations([{ sha: "a".repeat(40), author: "someone@gmail.com", committer: "noreply@github.com", body: "x\n\nCo-authored-by: A <another@example.org>\n" }]);
  assert.deepEqual(v, ["aaaaaaa author s***@g***.com", "aaaaaaa co-author a***@e***.org"]);
  assert.ok(!v.join(" ").includes("someone") && !v.join(" ").includes("gmail"));
});
