/**
 * An OAuth-fixing reverse proxy that lets Microsoft Copilot Studio connect to
 * one Arcade MCP gateway that has a user source.
 *
 * Copilot Studio's MCP OAuth flow departs from the MCP authorization spec in
 * two ways that matter to Arcade:
 *
 * 1. It never sends `resource` (RFC 8707) on authorize or token. Arcade uses
 *    `resource` to pick the gateway, and with it the gateway's user source.
 *    Without it the user signs in against the wrong user source and the
 *    gateway rejects the token.
 * 2. With the "Dynamic" OAuth type it ignores the advertised
 *    `registration_endpoint` and posts Dynamic Client Registration to
 *    `register` resolved against the server URL, a path Arcade doesn't serve.
 *
 * The shim serves its own discovery metadata, forwards registration to
 * Arcade's real endpoint, pins `resource` to the one gateway it fronts on
 * authorize and token, and passes MCP traffic through unchanged. It stores
 * nothing and never logs a credential.
 *
 * The handler only uses web-standard `Request`/`Response`/`fetch`, so it runs
 * on Bun, Node, Vercel, Cloudflare Workers, Deno, or anything else that
 * speaks the Fetch API.
 */

export interface ShimConfig {
	/** Where the shim is served, e.g. https://mcp.example.com. */
	publicUrl: string;
	/** Slug of the one Arcade gateway this shim fronts. Any other slug is a 404. */
	gateway: string;
	/** Arcade's MCP API. Defaults to https://api.arcade.dev. */
	arcadeApiUrl?: string | undefined;
	/** Arcade's OAuth authorization server. Defaults to https://cloud.arcade.dev. */
	arcadeAuthUrl?: string | undefined;
	/**
	 * Also log MCP request and response bodies (tool arguments and results) to
	 * the `log` sink. Off by default: those bodies can hold user data.
	 */
	logBodies?: boolean | undefined;
	/** Build identifier included in every log line. */
	version?: string | undefined;
	fetch?: ((req: Request) => Promise<Response>) | undefined;
	/**
	 * Where each request's log entry goes. A returned promise is handed to the
	 * runtime's `waitUntil`, when the caller passes one, so serverless hosts
	 * don't freeze the export mid-flight.
	 */
	log?: ((entry: ShimLog) => unknown) | undefined;
}

/** The slice of a serverless execution context the shim uses. */
export interface ExecutionContext {
	waitUntil(promise: Promise<unknown>): void;
}

export type Route =
	| "health"
	| "resource_metadata"
	| "auth_metadata"
	| "register"
	| "authorize"
	| "token"
	| "mcp"
	| "not_found";

/** One request through the shim. Never holds a credential. */
export interface ShimLog {
	event: "mcp_shim_request";
	route: Route;
	method: string;
	path: string;
	status: number;
	duration_ms: number;
	gateway: string;
	version: string | undefined;
	headers: Record<string, string>;
	mcp_methods?: string[];
	mcp_tool?: string;
	mcp_session_id?: string;
	token_claims?: Record<string, unknown>;
	oauth?: Record<string, unknown>;
	request_body?: string;
	response_body?: string;
	error?: string;
}

export const USER_AGENT = "copilot-studio-mcp-shim";

const GATEWAY_SLUG = /^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/i;

const CREDENTIAL_HEADER = /authorization|cookie|token|secret|api-key|apikey/i;

export function loggableHeaders(headers: Headers): Record<string, string> {
	const out: Record<string, string> = {};
	headers.forEach((value, name) => {
		if (!CREDENTIAL_HEADER.test(name)) out[name] = value;
	});
	return out;
}

/** Hop-by-hop and framing headers; `fetch` sets its own. */
const NO_FORWARD = new Set([
	"host",
	"connection",
	"keep-alive",
	"transfer-encoding",
	"content-length",
	"accept-encoding",
	"te",
	"trailer",
	"upgrade",
	"proxy-connection",
]);

/** `fetch` decompresses, so the upstream encoding no longer applies. */
const NO_RETURN = new Set([
	"connection",
	"keep-alive",
	"transfer-encoding",
	"content-length",
	"content-encoding",
]);

function forwardHeaders(headers: Headers): Headers {
	const out = new Headers();
	headers.forEach((value, name) => {
		if (!NO_FORWARD.has(name.toLowerCase())) out.set(name, value);
	});
	// Arcade sits behind Cloudflare, which blocks some default user agents.
	if (!out.has("user-agent")) out.set("user-agent", USER_AGENT);
	return out;
}

function decodeBase64Url(value: string): string {
	const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
	const padded = base64.padEnd(
		base64.length + ((4 - (base64.length % 4)) % 4),
		"=",
	);
	const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
	return new TextDecoder().decode(bytes);
}

/**
 * Claims from the bearer token, decoded without verification (Arcade
 * verifies). Identity and audience only; the token itself is never logged.
 */
export function tokenClaims(
	headers: Headers,
): Record<string, unknown> | undefined {
	const match = /^Bearer\s+([^.\s]+)\.([^.\s]+)\.[^.\s]+$/i.exec(
		headers.get("authorization") ?? "",
	);
	if (!match?.[2]) return undefined;
	try {
		const claims = JSON.parse(decodeBase64Url(match[2])) as Record<
			string,
			unknown
		>;
		const keep = ["iss", "aud", "sub", "client_id", "scope", "exp"];
		return Object.fromEntries(
			Object.entries(claims).filter(([key]) => keep.includes(key)),
		);
	} catch {
		return undefined;
	}
}

/** JSON-RPC method names and the called tool, from an MCP request body. */
function mcpDetails(body: string): { methods?: string[]; tool?: string } {
	try {
		const parsed = JSON.parse(body) as unknown;
		const messages = (Array.isArray(parsed) ? parsed : [parsed]) as Array<{
			method?: unknown;
			params?: { name?: unknown };
		}>;
		const methods = messages
			.map((m) => m.method)
			.filter((m): m is string => typeof m === "string");
		const call = messages.find((m) => m.method === "tools/call");
		const tool = call?.params?.name;
		return {
			...(methods.length ? { methods } : {}),
			...(typeof tool === "string" ? { tool } : {}),
		};
	} catch {
		return {};
	}
}

/** OAuth form or JSON fields that are safe to log. */
const OAUTH_LOGGABLE = [
	"client_id",
	"grant_type",
	"response_type",
	"redirect_uri",
	"redirect_uris",
	"grant_types",
	"response_types",
	"scope",
	"resource",
	"client_name",
	"token_endpoint_auth_method",
	"error",
	"error_description",
	"expires_in",
	"token_type",
];

/** The requested scopes, plus `offline_access` so Arcade issues a refresh token. */
export function withOfflineAccess(scope: string | null): string {
	const scopes = (scope ?? "mcp").split(/\s+/).filter(Boolean);
	if (!scopes.includes("offline_access")) scopes.push("offline_access");
	return scopes.join(" ");
}

/**
 * Which credentials a token request or response carried, as booleans. The
 * values are never logged; whether a refresh token came back (and whether
 * one is ever sent) is what says why a Copilot connection goes stale.
 */
export function tokenPresence(
	source: Record<string, unknown>,
): Record<string, boolean> {
	const has = (key: string) =>
		typeof source[key] === "string" && (source[key] as string).length > 0;
	const out: Record<string, boolean> = {};
	for (const key of [
		"access_token",
		"refresh_token",
		"id_token",
		"code",
		"code_verifier",
	]) {
		if (key in source) out[`has_${key}`] = has(key);
	}
	if (!("refresh_token" in source) && "access_token" in source) {
		out.has_refresh_token = false;
	}
	return out;
}

function pick(source: Record<string, unknown>): Record<string, unknown> {
	return Object.fromEntries(
		Object.entries(source).filter(([key]) => OAUTH_LOGGABLE.includes(key)),
	);
}

function parseJson(text: string): Record<string, unknown> {
	try {
		const value = JSON.parse(text) as unknown;
		return typeof value === "object" && value !== null
			? (value as Record<string, unknown>)
			: {};
	} catch {
		return {};
	}
}

function json(body: unknown, status = 200): Response {
	return Response.json(body, { status });
}

/** One JSON line per request on stdout, without headers or bodies. */
export function consoleLog(entry: ShimLog): void {
	const { headers: _h, request_body: _q, response_body: _r, ...rest } = entry;
	console.log(JSON.stringify(rest));
}

function trimSlash(url: string): string {
	return url.replace(/\/+$/, "");
}

export function createShim(config: ShimConfig) {
	if (!GATEWAY_SLUG.test(config.gateway)) {
		throw new Error(`invalid gateway slug: ${JSON.stringify(config.gateway)}`);
	}
	const publicUrl = trimSlash(config.publicUrl);
	const arcadeApi = trimSlash(config.arcadeApiUrl ?? "https://api.arcade.dev");
	const arcadeAuth = trimSlash(
		config.arcadeAuthUrl ?? "https://cloud.arcade.dev",
	);
	const upstreamFetch = config.fetch ?? ((req: Request) => fetch(req));
	const log = config.log ?? consoleLog;
	const logBodies = config.logBodies ?? false;

	const gatewayPath = `/mcp/${config.gateway}`;
	const resource = `${arcadeApi}${gatewayPath}`;

	function route(method: string, path: string): Route {
		if (path === "/health") return "health";
		// With or without the trailing slash Copilot is told to use.
		if (
			path === `/.well-known/oauth-protected-resource${gatewayPath}` ||
			path === `/.well-known/oauth-protected-resource${gatewayPath}/`
		)
			return "resource_metadata";
		if (path === "/.well-known/oauth-authorization-server/oauth2")
			return "auth_metadata";
		if (
			method === "POST" &&
			(path === "/mcp/register" ||
				path === `${gatewayPath}/register` ||
				path === "/oauth2/register")
		)
			return "register";
		if (method === "GET" && path === "/oauth2/authorize") return "authorize";
		if (method === "POST" && path === "/oauth2/token") return "token";
		if (path === gatewayPath || path === `${gatewayPath}/`) return "mcp";
		return "not_found";
	}

	async function handle(
		req: Request,
		kind: Route,
		entry: Partial<ShimLog>,
	): Promise<Response> {
		switch (kind) {
			case "health":
				return json({ status: "healthy" });

			case "not_found":
				return json({ error: "not found" }, 404);

			// Discovery points at the shim, so a client that uses it still gets
			// `resource` pinned on authorize and token.
			case "resource_metadata":
				return json({
					resource: `${publicUrl}${gatewayPath}`,
					authorization_servers: [`${publicUrl}/oauth2`],
					bearer_methods_supported: ["header"],
					// offline_access, so a client that takes its scopes from here
					// asks for (and gets) a refresh token.
					scopes_supported: ["mcp", "offline_access"],
				});

			case "auth_metadata": {
				const res = await upstreamFetch(
					new Request(
						`${arcadeAuth}/.well-known/oauth-authorization-server/oauth2`,
						{ headers: { "user-agent": USER_AGENT } },
					),
				);
				if (!res.ok) return json({ error: "upstream metadata" }, 502);
				const meta = (await res.json()) as Record<string, unknown>;
				return json({
					...meta,
					issuer: `${publicUrl}/oauth2`,
					authorization_endpoint: `${publicUrl}/oauth2/authorize`,
					token_endpoint: `${publicUrl}/oauth2/token`,
					registration_endpoint: `${publicUrl}/oauth2/register`,
				});
			}

			case "authorize": {
				const target = new URL(`${arcadeAuth}/oauth2/authorize`);
				new URL(req.url).searchParams.forEach((value, key) => {
					target.searchParams.append(key, value);
				});
				target.searchParams.set("resource", resource);
				target.searchParams.set(
					"scope",
					withOfflineAccess(target.searchParams.get("scope")),
				);
				entry.oauth = pick(Object.fromEntries(target.searchParams));
				return Response.redirect(target.toString(), 302);
			}

			case "token": {
				const form = new URLSearchParams(await req.text());
				form.set("resource", resource);
				// Copilot's client is public (registered with no secret), but Power
				// Platform's refresh template sends `client_secret` anyway, and some
				// connectors send Basic auth. Arcade would refuse either for a
				// public client, so neither is passed on; the log still says
				// whether one was sent.
				const sentSecret =
					form.has("client_secret") ||
					/^basic /i.test(req.headers.get("authorization") ?? "");
				form.delete("client_secret");
				const headers = forwardHeaders(req.headers);
				headers.delete("authorization");
				const res = await upstreamFetch(
					new Request(`${arcadeAuth}/oauth2/token`, {
						method: "POST",
						headers,
						body: form,
					}),
				);
				const text = await res.text();
				const sent = Object.fromEntries(form);
				const answer = parseJson(text);
				entry.oauth = {
					request: {
						...pick(sent),
						...tokenPresence(sent),
						...(sentSecret ? { dropped_client_secret: true } : {}),
					},
					response: { ...pick(answer), ...tokenPresence(answer) },
				};
				return passBack(res, text);
			}

			case "register": {
				const body = await req.text();
				const res = await upstreamFetch(
					new Request(`${arcadeAuth}/oauth2/register`, {
						method: "POST",
						headers: forwardHeaders(req.headers),
						body,
					}),
				);
				const text = await res.text();
				entry.oauth = {
					request: pick(parseJson(body)),
					response: pick(parseJson(text)),
				};
				return passBack(res, text);
			}

			case "mcp": {
				const body =
					req.method === "GET" || req.method === "HEAD"
						? undefined
						: await req.text();
				const session = req.headers.get("mcp-session-id");
				const claims = tokenClaims(req.headers);
				if (body) {
					if (logBodies) entry.request_body = body;
					const { methods, tool } = mcpDetails(body);
					if (methods) entry.mcp_methods = methods;
					if (tool) entry.mcp_tool = tool;
				}
				if (session) entry.mcp_session_id = session;
				if (claims) entry.token_claims = claims;

				const res = await upstreamFetch(
					new Request(resource, {
						method: req.method,
						headers: forwardHeaders(req.headers),
						...(body === undefined ? {} : { body }),
					}),
				);
				const contentType = res.headers.get("content-type") ?? "";
				// Server-sent events stream straight through, unread.
				if (contentType.includes("text/event-stream") || !logBodies) {
					return passBack(res);
				}
				const text = await res.text();
				entry.response_body = text;
				return passBack(res, text);
			}
		}
	}

	/** Upstream response back to the client, discovery pointed at the shim. */
	function passBack(res: Response, text?: string): Response {
		const headers = new Headers();
		res.headers.forEach((value, name) => {
			if (NO_RETURN.has(name.toLowerCase())) return;
			headers.set(
				name,
				name.toLowerCase() === "www-authenticate"
					? value
							.replaceAll(
								`${arcadeApi}/.well-known/`,
								`${publicUrl}/.well-known/`,
							)
							// Clients that take scope from the challenge ask for a
							// refresh token too.
							.replace(/scope="mcp"/, 'scope="mcp offline_access"')
					: value,
			);
		});
		return new Response(text ?? res.body, { status: res.status, headers });
	}

	return async function fetchHandler(
		req: Request,
		ctx?: ExecutionContext,
	): Promise<Response> {
		const started = performance.now();
		const { pathname } = new URL(req.url);
		const kind = route(req.method, pathname);
		const entry: Partial<ShimLog> = {};
		let res: Response;
		try {
			res = await handle(req, kind, entry);
		} catch (err) {
			entry.error = String(err);
			res = json({ error: "upstream unavailable" }, 502);
		}
		if (kind !== "health") {
			const pending = log({
				event: "mcp_shim_request",
				route: kind,
				method: req.method,
				path: pathname,
				status: res.status,
				duration_ms: Math.round((performance.now() - started) * 100) / 100,
				gateway: config.gateway,
				version: config.version,
				headers: loggableHeaders(req.headers),
				...entry,
			});
			if (ctx && pending instanceof Promise) ctx.waitUntil(pending);
		}
		return res;
	};
}
