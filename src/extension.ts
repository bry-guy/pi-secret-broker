// pi-secret-broker: the `broker_run` tool for role broker actions, and secret resolution for pi-mounts.
// Roles and signed grants come from pi-projects in the same pi process (globalThis[Symbol.for("pi-projects.v1")]).
import { join } from "node:path";
import { Type } from "@earendil-works/pi-ai";
import { createLocalBashOperations, SettingsManager, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";
import { audit, defaultAuditFile, execute, prepare } from "./broker.ts";
import { guardWrite, lineFilter, redact, redactMessages, redactToolResult } from "./redact.ts";
import { resolveSecrets, resolveSource } from "./secrets.ts";

(globalThis as any)[Symbol.for("pi-secret-broker.v1")] = { resolveSecrets, resolveSource, redact };

const projects = () => (globalThis as any)[Symbol.for("pi-projects.v1")];

function roleFor(ctx: ExtensionContext) {
	const api = projects();
	if (!api) throw new Error("pi-secret-broker needs pi-projects (roles and grants)");
	const project = api.projectForCwd(ctx.cwd);
	if (!project) throw new Error("This session is not in a pi project");
	const r = api.sessionRole(project, process.env, { fetch: false });
	if (!r.roleId || !r.role) throw new Error(`No role for this session${r.problem ? `: ${r.problem}` : ""}`);
	return { api, project, roleId: r.roleId as string, role: r.role, sources: api.trustedGrants().grants.sources[r.roleId] };
}

export default function (pi: ExtensionAPI) {
	// Redaction runs in every session, with or without a project or role.
	pi.on("tool_result", (e) => redactToolResult(e));
	pi.on("context", (e) => {
		const messages = redactMessages(e.messages);
		return messages === e.messages ? undefined : { messages };
	});
	pi.on("tool_call", (e) => guardWrite(e.toolName, e.input as Record<string, unknown>));
	// `!command` output: pi's own local shell, with output filtered. The first user_bash handler that returns wins, so
	// an extension that needs to run `!` commands elsewhere must load before this one.
	pi.on("user_bash", (e) => {
		const local = createLocalBashOperations({ shellPath: SettingsManager.create(e.cwd).getShellPath() });
		return {
			operations: {
				exec: (command, cwd, o) => {
					const f = lineFilter(o.onData);
					return local.exec(command, cwd, { ...o, onData: f.push }).finally(f.end);
				},
			},
		};
	});

	pi.registerTool({
		name: "broker_run",
		label: "Broker",
		description:
			"Run one of your role's host actions (listed in the system prompt as broker_run actions) with the role's secrets. " +
			"You never see the secrets; output has them redacted. checkout is repos/<repo> or worktrees/<repo>/<branch>.",
		parameters: Type.Object({
			action: Type.String({ description: "Action name from the role" }),
			checkout: Type.String({ description: "Checkout relative to the project root, e.g. worktrees/infra/feat-x" }),
			args: Type.Optional(Type.Record(Type.String(), Type.String(), { description: "Action args, if it takes any" })),
		}),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const { api, project, roleId, role, sources } = roleFor(ctx);
			const req = { projectPath: project.path, roleId, actions: role.broker, sources, action: params.action, checkout: params.checkout, args: params.args };
			const p = prepare(req);
			const log = defaultAuditFile(api.agentDir());
			if (p.action.approve === "ask") {
				const ok = ctx.hasUI && (await ctx.ui.confirm("Broker action", `${roleId}: ${p.argv.join(" ")}\nin ${p.cwd}`));
				if (!ok) {
					audit(log, { project: project.name, role: roleId, action: params.action, argv: p.argv, refused: true });
					throw new Error("Bryan declined this broker action (or no one was there to approve it).");
				}
			}
			const r = await execute(p, { signal });
			audit(log, { project: project.name, role: roleId, action: params.action, argv: p.argv, cwd: p.cwd, exit: r.exitCode, timedOut: r.timedOut, session: ctx.sessionManager.getSessionFile?.() });
			const head = `${params.action}: exit ${r.exitCode}${r.timedOut ? " (timed out)" : ""}`;
			return { content: [{ type: "text", text: `${head}\n${r.output}` }], details: { exitCode: r.exitCode } };
		},
	});
}
