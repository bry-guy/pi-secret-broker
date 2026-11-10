// Best-effort secret redaction for every session: keeps secret values out of transcripts and model requests.
// Not a security boundary: anything encoded, split or transformed gets through.
import { basename } from "node:path";
import { StringDecoder } from "node:string_decoder";

const SECRET_NAME = /token|secret|password|passwd|credential|api_?key|private_?key/i;
const MIN = 8;
const mark = (kind: string) => `[redacted:${kind}]`;

/** Token-shaped strings, realistic lengths only. Order matters: PEM blocks first. */
export const PATTERNS: [name: string, re: RegExp][] = [
	["private-key", /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g],
	["github-token", /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})/g],
	["anthropic-key", /\bsk-ant-[A-Za-z0-9_-]{32,}/g],
	["openai-key", /\bsk-(?!ant-)[A-Za-z0-9_-]{32,}/g],
	["slack-token", /\bxox[bpa]-[A-Za-z0-9-]{20,}/g],
	["aws-access-key-id", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
	["1password-service-account-token", /\bops_[A-Za-z0-9+/=_-]{60,}/g],
	["jwt", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g],
];

/** Values redacted wherever they appear: role secrets the broker resolved, and values rules 2 and 3 caught. */
const known = new Map<string, string>();
const LEARNED_MAX = 500;

export function rememberSecret(kind: string, value: string): void {
	if (value.length < MIN || known.has(value)) return;
	known.set(value, kind);
	if (known.size > LEARNED_MAX) known.delete(known.keys().next().value!);
}

/** Paths and URLs without credentials are not secrets (SSH_AUTH_SOCK, *_TOKEN_FILE, ...). */
function secretLike(v: string): boolean {
	if (v.length < MIN || v.startsWith("[redacted:")) return false;
	if (/^(?:\/|~\/|\.\.?\/)/.test(v)) return false;
	const url = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(v);
	return !url || url[1].includes("@");
}

function knownValues(env: NodeJS.ProcessEnv): [string, string][] {
	const all = new Map(known);
	for (const [k, v] of Object.entries(env)) if (v && SECRET_NAME.test(k) && secretLike(v)) all.set(v, k);
	return [...all].sort((a, b) => b[0].length - a[0].length);
}

const ASSIGNMENT = /^([ \t]*(?:export[ \t]+)?)([A-Z][A-Z0-9_]*)=(.*)$/gm;

export interface RedactOptions {
	/** Rule 3: `NAME=value` lines. Only for shell output and dotenv-file reads. */
	assignments?: boolean;
	env?: NodeJS.ProcessEnv;
}

export function redact(text: string, { assignments = false, env = process.env }: RedactOptions = {}): string {
	let out = text;
	for (const [v, kind] of knownValues(env)) if (out.includes(v)) out = out.split(v).join(mark(kind));
	for (const [name, re] of PATTERNS) {
		out = out.replace(re, (m) => {
			if (name === "jwt" && m.length < 60) return m;
			rememberSecret(name, m);
			return mark(name);
		});
	}
	if (assignments) {
		out = out.replace(ASSIGNMENT, (line, pre: string, name: string, raw: string) => {
			const v = raw.trim().replace(/^(["'])(.*)\1$/, "$2");
			// `$VAR`, `${{ secrets.X }}`, `<your-token>`: a reference or placeholder (scripts, CI files), not a value.
			if (!SECRET_NAME.test(name) || !secretLike(v) || /^[$<]/.test(v)) return line;
			rememberSecret(name, v);
			return `${pre}${name}=${mark(name)}`;
		});
	}
	return out;
}

/** Dotenv-style files, whose reads get rule 3. Examples and templates are left readable. */
export function isDotenvPath(path: unknown): boolean {
	if (typeof path !== "string") return false;
	const b = basename(path);
	if (/^\.env\.(?:example|sample|template)$/.test(b)) return false;
	return b === ".env" || b === ".envrc" || b.startsWith(".env.") || b.endsWith(".env");
}

type Part = { type: string; text?: string; [k: string]: unknown };

function redactJson<T>(value: T, opts: RedactOptions): T {
	if (value === undefined) return value;
	const s = JSON.stringify(value);
	const r = redact(s, opts);
	if (r === s) return value;
	try {
		return JSON.parse(r);
	} catch {
		return value; // a match that spanned JSON structure: leave it rather than break the tool call
	}
}

/** `tool_result`: replacement fields, or undefined when nothing changed. */
export function redactToolResult<P extends { type: string; text?: string }, S>(
	e: { toolName: string; input: Record<string, unknown>; content: P[]; structuredContent?: S },
	env: NodeJS.ProcessEnv = process.env,
): { content: P[]; structuredContent?: S } | undefined {
	const opts = { env, assignments: e.toolName === "bash" || (e.toolName === "read" && isDotenvPath(e.input?.path)) };
	let changed = false;
	const content = e.content.map((p) => {
		if (p.type !== "text" || typeof p.text !== "string") return p;
		const text = redact(p.text, opts);
		if (text === p.text) return p;
		changed = true;
		return { ...p, text };
	});
	if (!changed) return undefined;
	return e.structuredContent === undefined ? { content } : { content, structuredContent: redactJson(e.structuredContent, opts) };
}

function redactParts(parts: unknown, opts: RedactOptions): unknown {
	if (typeof parts === "string") return redact(parts, opts);
	if (!Array.isArray(parts)) return parts;
	let changed = false;
	const out = parts.map((p: Part) => {
		let q = p;
		if (p?.type === "text" && typeof p.text === "string") {
			const text = redact(p.text, opts);
			if (text !== p.text) q = { ...p, text };
		} else if (p?.type === "toolCall" && p.arguments !== undefined) {
			const args = redactJson(p.arguments, opts);
			if (args !== p.arguments) q = { ...p, arguments: args };
		}
		if (q !== p) changed = true;
		return q;
	});
	return changed ? out : parts;
}

/** `context` backstop: rules 1, 2 and learned values. Returns the same array (and objects) when nothing matched. */
export function redactMessages<M extends Record<string, any>>(messages: M[], env: NodeJS.ProcessEnv = process.env): M[] {
	const opts = { env };
	let changed = false;
	const out = messages.map((m) => {
		let n = m;
		// `command`: what the user typed after `!`, stored beside its output.
		for (const key of ["content", "output", "summary", "command"] as const) {
			if (!(key in m)) continue;
			const v = redactParts(m[key], opts);
			if (v !== m[key]) n = { ...n, [key]: v };
		}
		if (n !== m) changed = true;
		return n;
	});
	return changed ? out : messages;
}

const MARKER = /\[redacted:[A-Za-z0-9_-]+\]/;
const GUARD_REASON = "This text was redacted when you read it. Leave that part of the file untouched (edit around it) or ask the user.";

/** `tool_call`: keeps redaction markers from being written back into files. */
export function guardWrite(toolName: string, input: Record<string, any>): { block: true; reason: string } | undefined {
	const texts =
		toolName === "write" ? [input.content] : toolName === "edit" ? [input.newText, ...(Array.isArray(input.edits) ? input.edits.map((e: any) => e?.newText) : [])] : [];
	return texts.some((t) => typeof t === "string" && MARKER.test(t)) ? { block: true, reason: GUARD_REASON } : undefined;
}

/** Streams shell output through `redact` (with rule 3) a line at a time; holds an open PEM block until it ends. */
export function lineFilter(emit: (data: Buffer) => void, env: NodeJS.ProcessEnv = process.env) {
	const decoder = new StringDecoder("utf8");
	let buf = "";
	const flush = (upTo: number) => {
		if (upTo <= 0) return;
		emit(Buffer.from(redact(buf.slice(0, upTo), { assignments: true, env })));
		buf = buf.slice(upTo);
	};
	return {
		push(data: Buffer) {
			buf += decoder.write(data);
			let cut = buf.lastIndexOf("\n") + 1;
			const open = buf.lastIndexOf("-----BEGIN");
			if (open >= 0 && !/-----END [^\n]*-----/.test(buf.slice(open)) && buf.length < 65_536) cut = Math.min(cut, open);
			flush(buf.length >= 65_536 ? buf.length : cut);
		},
		end() {
			buf += decoder.end();
			flush(buf.length);
		},
	};
}
