// Resolving role secrets on the host. Sources come from the signed grants file (pi-projects), per role:
//   keychain:<service>   macOS Keychain generic password (account = $USER)
//   op://vault/item/field  1Password, read with the role's OP_SERVICE_ACCOUNT_TOKEN only
//   env:NAME | file:path | value:literal
// `op` never falls back to Bryan's desktop app: it runs with a clean env holding only the role's token.
import { execFileSync } from "node:child_process";
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
		default:
			throw new Error(`unknown secret source "${scheme}:"`);
	}
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
			out[name] = resolveSource(s, s.startsWith("op:") ? token() : undefined);
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
