// Role broker actions: fixed argv templates from the role file (merged on origin), run on the host with the role's
// secrets in a clean env. The agent picks the action, the checkout and validated args; it never sees the secrets.
// Agent-written code in the checkout runs with those secrets (e.g. tofu modules): accepted, since the threat model
// is mistakes, not injection.
import { spawn } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, realpathSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { cleanEnv, redact, resolveSecrets, type Sources } from "./secrets.ts";

export interface BrokerAction {
	description?: string;
	run: string[];
	cwd?: string;
	env?: string[];
	approve?: "auto" | "ask";
	args?: Record<string, string>;
}

export interface RunRequest {
	projectPath: string;
	roleId: string;
	actions: Record<string, BrokerAction> | undefined;
	sources: Sources | undefined;
	action: string;
	/** Checkout relative to the project: repos/<repo> or worktrees/<repo>/<branch> */
	checkout: string;
	args?: Record<string, string>;
	timeoutMs?: number;
	signal?: AbortSignal;
	auditFile?: string;
}

export interface Prepared {
	argv: string[];
	cwd: string;
	env: Record<string, string>;
	secrets: Record<string, string>;
	action: BrokerAction;
}

const MAX_OUTPUT = 60_000;

/** Validates the request and resolves secrets; throws with a message fit for the agent. */
export function prepare(req: RunRequest): Prepared {
	const action = req.actions?.[req.action];
	if (!action) throw new Error(`Role ${req.roleId} has no broker action "${req.action}". Actions: ${Object.keys(req.actions ?? {}).join(", ") || "none"}`);
	const repo = req.roleId.split("/")[0];
	const root = realpathSync(req.projectPath);
	const abs = resolve(root, req.checkout);
	if (!existsSync(abs)) throw new Error(`No checkout at ${req.checkout}`);
	const checkout = realpathSync(abs);
	const rel = relative(root, checkout).split(sep);
	const ok = (rel[0] === "repos" && rel[1] === repo && rel.length === 2) || (rel[0] === "worktrees" && rel[1] === repo && rel.length >= 3);
	if (!ok) throw new Error(`Checkout must be repos/${repo} or worktrees/${repo}/<branch> (role ${req.roleId})`);
	const cwd = resolve(checkout, action.cwd ?? ".");
	if (cwd !== checkout && !cwd.startsWith(checkout + sep)) throw new Error("Action cwd escapes the checkout");

	const args = req.args ?? {};
	for (const k of Object.keys(args)) if (!action.args?.[k]) throw new Error(`Action ${req.action} takes no arg "${k}"`);
	const argv = action.run.map((part) =>
		part.replace(/\{(\w+)\}/g, (_, name: string) => {
			const pattern = action.args?.[name];
			const v = args[name];
			if (!pattern || v === undefined) throw new Error(`Action ${req.action} needs arg "${name}"`);
			if (!new RegExp(`^(?:${pattern})$`).test(v)) throw new Error(`Arg ${name}="${v}" does not match ${pattern}`);
			return v;
		}),
	);
	const secrets = resolveSecrets(req.sources, action.env ?? []);
	return { argv, cwd, env: cleanEnv(secrets), secrets, action };
}

export interface RunResult {
	exitCode: number | null;
	output: string;
	timedOut: boolean;
}

export function execute(p: Prepared, { timeoutMs = 15 * 60_000, signal }: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<RunResult> {
	return new Promise((done, fail) => {
		const child = spawn(p.argv[0], p.argv.slice(1), { cwd: p.cwd, env: p.env, stdio: ["ignore", "pipe", "pipe"], detached: true });
		let out = "";
		let timedOut = false;
		const add = (b: Buffer) => {
			out += b.toString();
			if (out.length > MAX_OUTPUT * 2) out = out.slice(-MAX_OUTPUT);
		};
		child.stdout.on("data", add);
		child.stderr.on("data", add);
		const kill = () => {
			try {
				process.kill(-child.pid!, "SIGTERM");
				setTimeout(() => {
					try {
						process.kill(-child.pid!, "SIGKILL");
					} catch {}
				}, 5000).unref();
			} catch {}
		};
		const timer = setTimeout(() => {
			timedOut = true;
			kill();
		}, timeoutMs);
		signal?.addEventListener("abort", kill, { once: true });
		child.on("error", (e) => {
			clearTimeout(timer);
			fail(e);
		});
		child.on("close", (code) => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", kill);
			let text = redact(out, p.secrets);
			if (text.length > MAX_OUTPUT) text = `…(truncated)\n${text.slice(-MAX_OUTPUT)}`;
			done({ exitCode: code, output: text, timedOut });
		});
	});
}

export function audit(file: string, entry: Record<string, unknown>): void {
	try {
		mkdirSync(dirname(file), { recursive: true });
		appendFileSync(file, `${JSON.stringify({ time: new Date().toISOString(), ...entry })}\n`, { mode: 0o600 });
	} catch {
		// auditing never blocks the action
	}
}

export function defaultAuditFile(agentDir: string): string {
	return join(agentDir, "pi-secret-broker", "audit.jsonl");
}
