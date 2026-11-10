// Every fake token is built at runtime so this file holds nothing token-shaped.
import assert from "node:assert/strict";
import { test } from "node:test";

const { redact, redactToolResult, redactMessages, guardWrite, lineFilter, isDotenvPath } = await import("../src/redact.ts");

const env = {};
const r = (text: string, opts = {}) => redact(text, { env, ...opts });
const b64 = (n: number) => "Ab1".repeat(Math.ceil(n / 3)).slice(0, n);

const hits: [string, string][] = [
	["github-token", "gh" + "p_" + b64(36)],
	["github-token", "gh" + "s_" + b64(40)],
	["github-token", "github" + "_pat_" + b64(82)],
	["anthropic-key", "sk-" + "ant-api03-" + b64(80)],
	["openai-key", "sk-" + "proj-" + b64(48)],
	["slack-token", "xo" + "xb-" + "1234567890-" + b64(24)],
	["aws-access-key-id", "AK" + "IA" + "ABCDEFGH23456789"],
	["1password-service-account-token", "op" + "s_" + b64(120)],
	["jwt", "ey" + "J" + b64(30) + "." + "ey" + "J" + b64(40) + "." + b64(43)],
	["private-key", "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" + b64(70) + "\n" + b64(30) + "\n-----END " + "OPENSSH PRIVATE KEY-----"],
];

test("each pattern hits a realistic token", () => {
	for (const [kind, tok] of hits) assert.equal(r(`x ${tok} y`), `x [redacted:${kind}] y`, kind);
});

test("near-misses, prose and code are untouched", () => {
	const misses = [
		"gh" + "p_" + b64(10),
		"gh" + "p_",
		"sk-learn is a library; sk-" + "ant-short",
		"sk-" + b64(20),
		"xo" + "xb-123",
		"AK" + "IA" + "SHORT",
		"op" + "s_" + b64(20),
		"ey" + "J" + "a.b.c",
		"-----BEGIN " + "PUBLIC KEY-----",
		"const token = getToken(); const apiKey = process.env.API_KEY;",
		'{"password": "hunter2hunter2"}',
		"The secret to good tokens is a long password.",
	];
	for (const m of misses) assert.equal(r(m), m, m);
});

test("env-derived values are redacted; paths and plain URLs are not", () => {
	const e = { MY_API_KEY: "q9w8e7r6t5y4", SSH_AUTH_SOCK: "/tmp/agent.sock", TOKEN_FILE: "/run/secrets/x", TOKEN_URL: "https://example.com/oauth", DB_PASSWORD: "short", HOME: "/home/someone-long" };
	const text = "q9w8e7r6t5y4 /tmp/agent.sock /run/secrets/x https://example.com/oauth short";
	assert.equal(redact(text, { env: e }), "[redacted:MY_API_KEY] /tmp/agent.sock /run/secrets/x https://example.com/oauth short");
	assert.equal(redact("https://u:pw@h/x", { env: { GIT_CREDENTIAL_URL: "https://u:pw@h/x" } }), "[redacted:GIT_CREDENTIAL_URL]");
});

test("assignment lines: env dump and dotenv read, not source files", () => {
	const dump = "HOME=/home/x\nGITHUB_TOKEN=abcdefgh12345\nexport DB_PASSWORD='p4ssw0rd!x'\nPASSWORD_LEN=12\nNAME=abcdefghijk";
	const tool = (toolName: string, path: string | undefined, text: string) =>
		redactToolResult({ toolName, input: path ? { path } : { command: "env" }, content: [{ type: "text", text }] }, env);
	assert.equal(
		tool("bash", undefined, dump)?.content[0].text,
		"HOME=/home/x\nGITHUB_TOKEN=[redacted:GITHUB_TOKEN]\nexport DB_PASSWORD=[redacted:DB_PASSWORD]\nPASSWORD_LEN=12\nNAME=abcdefghijk",
	);
	assert.match(tool("read", "/p/.env.local", "API_KEY=zzzzyyyyxxxx")!.content[0].text!, /API_KEY=\[redacted:API_KEY\]/);
	assert.equal(tool("read", "/p/src/config.ts", "SOURCE_TOKEN=notasecretjustcode"), undefined);
	assert.equal(tool("read", "/p/.env.example", "EXAMPLE_TOKEN=placeholder-value"), undefined);
	assert.deepEqual(["/a/.env", "/a/.envrc", "/a/.env.prod", "/a/prod.env", "/a/.env.sample", "/a/env.ts"].map(isDotenvPath), [true, true, true, true, false, false]);
});

test("learned values are caught later in plain text and in the context backstop", () => {
	const v = "learned-" + b64(10);
	r(`OTHER_SECRET=${v}`, { assignments: true });
	assert.equal(r(`it was ${v}.`), "it was [redacted:OTHER_SECRET].");
	const tok = "gh" + "o_" + b64(36);
	r(tok);
	const msgs = [{ role: "user", content: `see ${tok}` }];
	assert.equal(redactMessages(msgs, env)[0].content, "see [redacted:github-token]");
});

test("context: same array when nothing matched, only changed messages copied", () => {
	const msgs = [
		{ role: "user", content: [{ type: "text", text: "hello" }] },
		{ role: "assistant", content: [{ type: "toolCall", arguments: { command: "ls" } }] },
		{ role: "bashExecution", output: "ok" },
	];
	assert.equal(redactMessages(msgs, env), msgs);
	const tok = "AK" + "IA" + "ZYXWVUTS23456789";
	const more = [...msgs, { role: "toolResult", content: [{ type: "text", text: tok }, { type: "image", data: "x" }] }];
	const out = redactMessages(more, env);
	assert.notEqual(out, more);
	assert.equal(out[0], more[0]);
	assert.equal((out[3].content as any)[0].text, "[redacted:aws-access-key-id]");
	assert.equal((out[3].content as any)[1], (more[3].content as any)[1]);
	// rule 3 is not applied in context
	const line = [{ role: "user", content: "FOO_TOKEN=only-in-context-1" }];
	assert.equal(redactMessages(line, env), line);
});

test("write/edit guard", () => {
	assert.equal(guardWrite("write", { path: "a", content: "X=[redacted:X]" })?.block, true);
	assert.equal(guardWrite("edit", { path: "a", edits: [{ oldText: "a", newText: "[redacted:jwt]" }] })?.block, true);
	assert.equal(guardWrite("edit", { path: "a", oldText: "a", newText: "[redacted:jwt]" })?.block, true);
	assert.equal(guardWrite("write", { path: "a", content: "normal" }), undefined);
	assert.equal(guardWrite("bash", { command: "echo [redacted:x]" }), undefined);
	// Code and docs that only mention the prefix or a placeholder kind stay editable.
	assert.equal(guardWrite("write", { path: "a", content: 'if (v.startsWith("[redacted:")) return; // shows [redacted:<kind>]' }), undefined);
});

test("no secrets: identical text, tool_result unchanged", () => {
	const t = "plain output\nwith lines and code: const x = 1;";
	assert.equal(r(t, { assignments: true }), t);
	assert.equal(redactToolResult({ toolName: "bash", input: {}, content: [{ type: "text", text: t }] }, env), undefined);
});

test("user_bash line filter redacts across chunk boundaries", () => {
	const tok = "gh" + "u_" + b64(36);
	const key = hits.at(-1)![1];
	let out = "";
	const f = lineFilter((d) => (out += d.toString()), env);
	const all = `a ${tok}\nAPI_TOKEN=abcdefgh9\n${key}\ntail`;
	for (let i = 0; i < all.length; i += 7) f.push(Buffer.from(all.slice(i, i + 7)));
	f.end();
	assert.equal(out, "a [redacted:github-token]\nAPI_TOKEN=[redacted:API_TOKEN]\n[redacted:private-key]\ntail");
});

test("assignment lines: references and placeholders are not values", () => {
	const text = ["API_TOKEN=${1:-fallback-value}", "GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }}", "export DB_PASSWORD=$OTHER_PASSWORD", "MY_SECRET=<your-secret-here>"].join("\n");
	assert.equal(redact(text, { assignments: true, env: {} }), text);
	assert.equal(redact("${1:-fallback-value} and $OTHER_PASSWORD", { env: {} }), "${1:-fallback-value} and $OTHER_PASSWORD", "nothing was learned");
});
