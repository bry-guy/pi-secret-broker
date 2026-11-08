// Resolving role secrets on the host. Sources come from the signed grants file (pi-projects), per role:
//   keychain:<service>   macOS Keychain generic password (account = $USER)
//   op://vault/item/field  1Password, read with the role's OP_SERVICE_ACCOUNT_TOKEN only
//   env:NAME | file:path | value:literal
//   github-app:op://vault/item  GitHub App installation token (1 h), minted from the item's app-id, private-key
//                               and repos fields (token limited to those repos); the App must be installed on exactly one account
// `op` never falls back to Bryan's desktop app: it runs with a clean env holding only the role's token.
import { execFileSync } from "node:child_process";
import { createSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir, userInfo } from "node:os";

export type Sources = Record<string, string>;

/** Minimal host env for subprocesses: nothing from Bryan's session (no SSH agent, no OP_*, no tokens). */
export function cleanEnv(extra: Record<string, string> = {}): Record<string, string> {
	const keep = ["PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "SHELL"];
	const env: Record<string, string> = { TERM: "dumb" };
	for (const k of keep) if (process.env[k]) env[k] = process.env[k]!;
	return { ...env, ...extra };
}

function keychain(service: string): string {
	return execFileSync("security", ["find-generic-password", "-s", service, "-a", userInfo().username, "-w"], {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "ignore"],
	}).replace(/\n$/, "");
}

/** Resolves one source. `opToken` is the role's service-account token, needed for op:// sources. */
export function resolveSource(source: string, opToken?: string): string {
	const i = source.indexOf(":");
	const scheme = source.slice(0, i);
	const rest = source.slice(i + 1);
	switch (scheme) {
		case "keychain":
			return keychain(rest);
		case "env":
			if (process.env[rest] === undefined) throw new Error(`env ${rest} is not set`);
			return process.env[rest]!;
		case "file":
			return readFileSync(rest.replace(/^~(?=\/)/, homedir()), "utf8").trim();
		case "value":
			return rest;
		case "op":
			if (!opToken) throw new Error("op:// needs an OP_SERVICE_ACCOUNT_TOKEN source for this role (never Bryan's desktop app)");
			return execFileSync("op", ["read", "--no-newline", source], {
				encoding: "utf8",
				env: cleanEnv({ OP_SERVICE_ACCOUNT_TOKEN: opToken }),
				stdio: ["ignore", "pipe", "pipe"],
				timeout: 30_000,
			});
		case "github-app":
			if (!opToken) throw new Error("github-app: needs an OP_SERVICE_ACCOUNT_TOKEN source for this role");
			return githubAppToken(rest, opToken);
		default:
			throw new Error(`unknown secret source "${scheme}:"`);
	}
}

const appTokens = new Map<string, { token: string; expires: number }>();

/** GitHub App installation token, cached until 15 min before it expires. */
function githubAppToken(item: string, opToken: string): string {
	const cached = appTokens.get(item);
	if (cached && cached.expires - Date.now() > 15 * 60_000) return cached.token;
	const op = (field: string) => resolveSource(`${item}/${field}`, opToken);
	const now = Math.floor(Date.now() / 1000);
	const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
	const unsigned = `${b64({ alg: "RS256", typ: "JWT" })}.${b64({ iat: now - 60, exp: now + 540, iss: op("app-id").trim() })}`;
	const jwt = `${unsigned}.${createSign("RSA-SHA256").update(unsigned).sign(op("private-key")).toString("base64url")}`;
	const gh = (method: string, path: string, body?: object) =>
		JSON.parse(
			execFileSync("curl", ["-fsS", "-X", method, "-H", "Accept: application/vnd.github+json", "-H", "@-", ...(body ? ["-d", JSON.stringify(body)] : []), `https://api.github.com${path}`], {
				encoding: "utf8",
				input: `Authorization: Bearer ${jwt}\n`,
				env: cleanEnv(),
				timeout: 30_000,
			}),
		);
	const installs = gh("GET", "/app/installations") as { id: number }[];
	if (installs.length !== 1) throw new Error(`the App has ${installs.length} installations, expected 1`);
	// The token covers only the item's `repos` (comma-separated names), whatever repos the installation allows.
	const repos = op("repos").split(",").map((r) => r.trim()).filter(Boolean);
	const res = gh("POST", `/app/installations/${installs[0].id}/access_tokens`, { repositories: repos }) as { token: string; expires_at: string };
	appTokens.set(item, { token: res.token, expires: Date.parse(res.expires_at) });
	return res.token;
}

/** Resolves the named secrets from a role's sources. Throws naming the first one that fails. */
export function resolveSecrets(sources: Sources | undefined, names: string[]): Record<string, string> {
	const src = sources ?? {};
	const out: Record<string, string> = {};
	let opToken: string | undefined;
	const token = () => {
		if (opToken === undefined && src.OP_SERVICE_ACCOUNT_TOKEN && !src.OP_SERVICE_ACCOUNT_TOKEN.startsWith("op:")) {
			opToken = resolveSource(src.OP_SERVICE_ACCOUNT_TOKEN);
		}
		return opToken;
	};
	for (const name of names) {
		const s = src[name];
		if (!s) throw new Error(`no source for secret ${name}`);
		try {
			out[name] = resolveSource(s, /^(op|github-app):/.test(s) ? token() : undefined);
		} catch (e) {
			throw new Error(`secret ${name} (${s.split(":")[0]}): ${(e as Error).message.split("\n")[0]}`);
		}
	}
	return out;
}

/** Replaces secret values in text, longest first. Short values (< 6 chars) are left alone to avoid noise. */
export function redact(text: string, secrets: Record<string, string>): string {
	let out = text;
	for (const [name, v] of Object.entries(secrets).sort((a, b) => b[1].length - a[1].length)) {
		if (v.length >= 6) out = out.split(v).join(`[${name}]`);
	}
	return out;
}
