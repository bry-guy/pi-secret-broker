import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const { prepare, execute } = await import("../src/broker.ts");
const { resolveSecrets, redact, cleanEnv } = await import("../src/secrets.ts");

function project() {
	const root = realpathSync(mkdtempSync(join(tmpdir(), "broker-")));
	for (const d of ["repos/infra/sub", "repos/other", "worktrees/infra/feat"]) mkdirSync(join(root, d), { recursive: true });
	return root;
}
const actions = {
	echo: { run: ["sh", "-c", "echo token=$TOKEN; echo $SSH_AUTH_SOCK $OP_SESSION_x; pwd"], env: ["TOKEN"], cwd: "sub" },
	plan: { run: ["echo", "plan", "{dir}"], args: { dir: "selfhost/[a-z-]+" } },
	sleep: { run: ["sleep", "30"] },
};
const base = (root: string, over = {}) => ({ projectPath: root, roleId: "infra/dev", actions, sources: { TOKEN: "value:s3cr3t-value" }, action: "echo", checkout: "repos/infra", ...over });

test("runs in the role repo checkout with only role secrets in a clean env, output redacted", async () => {
	process.env.SSH_AUTH_SOCK = "/tmp/agent.sock";
	process.env.OP_SESSION_x = "bryan";
	const root = project();
	const p = prepare(base(root));
	assert.equal(p.cwd, join(root, "repos/infra/sub"));
	assert.equal(p.env.SSH_AUTH_SOCK, undefined);
	const r = await execute(p);
	assert.equal(r.exitCode, 0);
	assert.match(r.output, /token=\[TOKEN\]/);
	assert.doesNotMatch(r.output, /s3cr3t|agent\.sock|bryan/);
});

test("refuses other repos, escapes, unknown actions and bad args", () => {
	const root = project();
	assert.throws(() => prepare(base(root, { checkout: "repos/other" })), /must be repos\/infra/);
	assert.throws(() => prepare(base(root, { checkout: "repos/infra/../../.." })), /must be|No checkout/);
	assert.throws(() => prepare(base(root, { action: "nope" })), /no broker action/);
	assert.throws(() => prepare(base(root, { action: "plan", args: { dir: "selfhost/x; rm -rf /" } })), /does not match/);
	assert.throws(() => prepare(base(root, { action: "plan" })), /needs arg/);
	assert.throws(() => prepare(base(root, { action: "plan", args: { dir: "selfhost/a", x: "1" } })), /takes no arg/);
	assert.deepEqual(prepare(base(root, { action: "plan", checkout: "worktrees/infra/feat", args: { dir: "selfhost/us-west" } })).argv, ["echo", "plan", "selfhost/us-west"]);
});

test("op:// never runs without the role's service-account token", () => {
	assert.throws(() => resolveSecrets({ X: "op://v/i/f" }, ["X"]), /OP_SERVICE_ACCOUNT_TOKEN/);
	assert.throws(() => resolveSecrets({}, ["X"]), /no source/);
});

test("timeouts kill the action", async () => {
	const root = project();
	const r = await execute(prepare(base(root, { action: "sleep" })), { timeoutMs: 300 });
	assert.equal(r.timedOut, true);
});

test("redact and cleanEnv", () => {
	assert.equal(redact("a abcdefgh b abc", { T: "abcdefgh", S: "abc" }), "a [T] b abc");
	process.env.GH_TOKEN = "x";
	assert.equal(cleanEnv().GH_TOKEN, undefined);
});
