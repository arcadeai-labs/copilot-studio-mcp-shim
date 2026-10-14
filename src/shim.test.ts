import { beforeEach, describe, expect, test } from "bun:test";
import { configFromEnv } from "./config.ts";
import {
	attributes,
	MAX_VALUE_LENGTH,
	otlpLogBody,
	parseOtlpHeaders,
} from "./otlp.ts";
import {
	createShim,
	MAX_OAUTH_BODY_BYTES,
	readBody,
	type ShimLog,
	tokenClaims,
} from "./shim.ts";

const PUBLIC = "https://mcp.example.test";
const RESOURCE = "https://api.arcade.dev/mcp/my-gateway";

let upstream: Request[] = [];
let reply: (req: Request) => Response = () => Response.json({});
const logs: ShimLog[] = [];

const shim = createShim({
	publicUrl: PUBLIC,
	gateway: "my-gateway",
	version: "abc1234",
	logBodies: true,
	fetch: async (req) => {
		upstream.push(req.clone() as Request);
		return reply(req);
	},
	log: (entry) => {
		logs.push(entry);
	},
});

beforeEach(() => {
	upstream = [];
	logs.length = 0;
	reply = () => Response.json({});
});

function call(path: string, init?: RequestInit) {
	return shim(new Request(`${PUBLIC}${path}`, init));
}

// A JWT-shaped token; only the payload matters to the shim.
const payload = Buffer.from(
	JSON.stringify({
		iss: "https://cloud.arcade.dev/oauth2",
		aud: RESOURCE,
		sub: "user-123",
		client_id: "client-1",
		secret_thing: "not logged",
	}),
).toString("base64url");
const TOKEN = `eyJhbGciOiJSUzI1NiJ9.${payload}.c2ln`;

describe("discovery", () => {
	test("protected resource metadata points at the shim", async () => {
		const res = await call(
			"/.well-known/oauth-protected-resource/mcp/my-gateway",
		);
		const slash = await call(
			"/.well-known/oauth-protected-resource/mcp/my-gateway/",
		);
		expect(slash.status).toBe(200);
		expect(await res.json()).toEqual({
			resource: `${PUBLIC}/mcp/my-gateway`,
			authorization_servers: [`${PUBLIC}/oauth2`],
			bearer_methods_supported: ["header"],
			scopes_supported: ["mcp", "offline_access"],
		});
	});

	test("authorization server metadata keeps Arcade's but routes via the shim", async () => {
		reply = () =>
			Response.json({
				issuer: "https://cloud.arcade.dev/oauth2",
				authorization_endpoint: "https://cloud.arcade.dev/oauth2/authorize",
				scopes_supported: ["mcp", "offline_access"],
			});
		const res = await call("/.well-known/oauth-authorization-server/oauth2");
		const meta = (await res.json()) as Record<string, unknown>;
		expect(meta.issuer).toBe(`${PUBLIC}/oauth2`);
		expect(meta.authorization_endpoint).toBe(`${PUBLIC}/oauth2/authorize`);
		expect(meta.registration_endpoint).toBe(`${PUBLIC}/oauth2/register`);
		expect(meta.scopes_supported).toEqual(["mcp", "offline_access"]);
	});
});

describe("registration", () => {
	for (const path of [
		"/mcp/register",
		"/mcp/my-gateway/register",
		"/oauth2/register",
	]) {
		test(`${path} goes to Arcade's registration endpoint`, async () => {
			reply = () => Response.json({ client_id: "new-client" }, { status: 201 });
			const res = await call(path, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ redirect_uris: ["https://cb.test/r"] }),
			});
			expect(res.status).toBe(201);
			expect(upstream[0]?.url).toBe("https://cloud.arcade.dev/oauth2/register");
			expect(logs[0]?.oauth).toEqual({
				request: { redirect_uris: ["https://cb.test/r"] },
				response: { client_id: "new-client" },
			});
		});
	}
});

describe("authorize", () => {
	test("adds resource for the gateway", async () => {
		const res = await call(
			"/oauth2/authorize?client_id=c1&response_type=code&scope=mcp",
		);
		expect(res.status).toBe(302);
		const location = new URL(res.headers.get("location") ?? "");
		expect(location.origin + location.pathname).toBe(
			"https://cloud.arcade.dev/oauth2/authorize",
		);
		expect(location.searchParams.get("client_id")).toBe("c1");
		expect(location.searchParams.get("resource")).toBe(RESOURCE);
		// Always asks for a refresh token, whatever the client asked for.
		expect(location.searchParams.get("scope")).toBe("mcp offline_access");
	});

	test("keeps offline_access once, and the client's own scopes", async () => {
		const res = await call(
			"/oauth2/authorize?client_id=c1&scope=offline_access%20mcp",
		);
		const location = new URL(res.headers.get("location") ?? "");
		expect(location.searchParams.get("scope")).toBe("offline_access mcp");
	});

	test("replaces any other resource, so it can only reach this gateway", async () => {
		const res = await call(
			`/oauth2/authorize?client_id=c1&resource=${encodeURIComponent("https://api.arcade.dev/mcp/other")}`,
		);
		const location = new URL(res.headers.get("location") ?? "");
		expect(location.searchParams.getAll("resource")).toEqual([RESOURCE]);
	});
});

describe("token", () => {
	test("adds resource and never logs codes or tokens", async () => {
		reply = () =>
			Response.json({
				access_token: "at-secret",
				refresh_token: "rt-secret",
				token_type: "Bearer",
				expires_in: 900,
			});
		const res = await call("/oauth2/token", {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: "grant_type=authorization_code&code=code-secret&code_verifier=v-secret&client_id=c1",
		});
		expect(((await res.json()) as { access_token: string }).access_token).toBe(
			"at-secret",
		);
		const sent = new URLSearchParams(await upstream[0]?.text());
		expect(sent.get("resource")).toBe(RESOURCE);
		expect(sent.get("code")).toBe("code-secret");

		const logged = JSON.stringify(logs);
		for (const secret of ["at-secret", "rt-secret", "code-secret", "v-secret"])
			expect(logged).not.toContain(secret);
		// Whether each credential was there, never its value.
		expect(logs[0]?.oauth).toEqual({
			request: {
				grant_type: "authorization_code",
				client_id: "c1",
				resource: RESOURCE,
				has_code: true,
				has_code_verifier: true,
			},
			response: {
				token_type: "Bearer",
				expires_in: 900,
				has_access_token: true,
				has_refresh_token: true,
			},
		});
	});

	test("a client secret is never passed on to Arcade (the client is public)", async () => {
		reply = () => Response.json({ access_token: "at", token_type: "Bearer" });
		await call("/oauth2/token", {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				authorization: `Basic ${Buffer.from("c1:x").toString("base64")}`,
			},
			body: "grant_type=refresh_token&refresh_token=rt&client_id=c1&client_secret=",
		});
		const sent = new URLSearchParams(await upstream[0]?.text());
		expect(sent.has("client_secret")).toBe(false);
		expect(upstream[0]?.headers.get("authorization")).toBeNull();
		expect(logs[0]?.oauth).toMatchObject({
			request: { dropped_client_secret: true },
		});
	});

	test("a refresh is logged as one, and a missing refresh token says so", async () => {
		reply = () =>
			Response.json({
				access_token: "at-2",
				token_type: "Bearer",
				expires_in: 900,
			});
		await call("/oauth2/token", {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: "grant_type=refresh_token&refresh_token=rt-old&client_id=c1",
		});
		const sent = new URLSearchParams(await upstream[0]?.text());
		expect(sent.get("resource")).toBe(RESOURCE);
		expect(logs[0]?.oauth).toMatchObject({
			request: { grant_type: "refresh_token", has_refresh_token: true },
			response: { has_access_token: true, has_refresh_token: false },
		});
		expect(JSON.stringify(logs)).not.toContain("rt-old");
	});
});

describe("mcp", () => {
	test("forwards to the gateway, with or without a trailing slash", async () => {
		for (const path of ["/mcp/my-gateway", "/mcp/my-gateway/"]) {
			upstream = [];
			reply = () =>
				Response.json(
					{ jsonrpc: "2.0", id: 1, result: {} },
					{ headers: { "mcp-session-id": "s-1" } },
				);
			const res = await call(path, {
				method: "POST",
				headers: {
					authorization: `Bearer ${TOKEN}`,
					"content-type": "application/json",
				},
				body: '{"jsonrpc":"2.0","id":1,"method":"initialize"}',
			});
			expect(res.status).toBe(200);
			expect(res.headers.get("mcp-session-id")).toBe("s-1");
			expect(upstream[0]?.url).toBe(RESOURCE);
			expect(upstream[0]?.headers.get("authorization")).toBe(`Bearer ${TOKEN}`);
		}
	});

	test("logs the call without the token", async () => {
		reply = () => Response.json({ jsonrpc: "2.0", id: 2, result: {} });
		await call("/mcp/my-gateway/", {
			method: "POST",
			headers: {
				authorization: `Bearer ${TOKEN}`,
				"mcp-session-id": "s-1",
			},
			body: '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"MicrosoftOutlookMail_ListEmails","arguments":{}}}',
		});
		const entry = logs[0];
		expect(entry?.route).toBe("mcp");
		expect(entry?.mcp_methods).toEqual(["tools/call"]);
		expect(entry?.mcp_tool).toBe("MicrosoftOutlookMail_ListEmails");
		expect(entry?.mcp_session_id).toBe("s-1");
		expect(entry?.token_claims).toEqual({
			iss: "https://cloud.arcade.dev/oauth2",
			aud: RESOURCE,
			sub: "user-123",
			client_id: "client-1",
		});
		expect(JSON.stringify(entry)).not.toContain(TOKEN);
		expect(entry?.headers.authorization).toBeUndefined();
	});

	test("points WWW-Authenticate discovery at the shim", async () => {
		reply = () =>
			new Response("{}", {
				status: 401,
				headers: {
					"www-authenticate": `Bearer resource_metadata="https://api.arcade.dev/.well-known/oauth-protected-resource/mcp/my-gateway", scope="mcp"`,
				},
			});
		const res = await call("/mcp/my-gateway", { method: "POST" });
		expect(res.status).toBe(401);
		expect(res.headers.get("www-authenticate")).toBe(
			`Bearer resource_metadata="${PUBLIC}/.well-known/oauth-protected-resource/mcp/my-gateway", scope="mcp offline_access"`,
		);
	});

	test("streams server-sent events without reading them", async () => {
		reply = () =>
			new Response("event: message\ndata: {}\n\n", {
				headers: { "content-type": "text/event-stream" },
			});
		const res = await call("/mcp/my-gateway", { method: "GET" });
		expect(await res.text()).toBe("event: message\ndata: {}\n\n");
		expect(logs[0]?.response_body).toBeUndefined();
	});
});

describe("everything else", () => {
	test("other gateways and paths are not proxied", async () => {
		for (const path of ["/mcp/other-gateway", "/pre", "/oauth2/revoke", "/"]) {
			const res = await call(path, { method: "POST" });
			expect(res.status).toBe(404);
		}
		expect(upstream).toHaveLength(0);
	});

	test("an upstream failure is a 502, logged", async () => {
		reply = () => {
			throw new Error("connection refused");
		};
		const res = await call("/mcp/my-gateway", {
			method: "POST",
			body: "{}",
		});
		expect(res.status).toBe(502);
		expect(logs[0]?.error).toContain("connection refused");
	});
});

describe("helpers", () => {
	test("tokenClaims ignores anything that isn't a JWT", () => {
		expect(
			tokenClaims(new Headers({ authorization: "Bearer opaque" })),
		).toBeUndefined();
	});

	test("OTLP attributes are capped and flagged", () => {
		const attrs = attributes({
			event: "mcp_shim_request",
			route: "mcp",
			method: "POST",
			path: "/mcp/my-gateway",
			status: 200,
			duration_ms: 1,
			gateway: "my-gateway",
			version: undefined,
			headers: {},
			response_body: "x".repeat(MAX_VALUE_LENGTH + 10),
		});
		const body = attrs.find((a) => a.key === "shim.response_body");
		expect(body?.value.stringValue).toHaveLength(MAX_VALUE_LENGTH);
		expect(
			attrs.find((a) => a.key === "shim.truncated")?.value.stringValue,
		).toBe("response_body");
	});
});

describe("logging bodies", () => {
	const quiet: ShimLog[] = [];
	const shimNoBodies = createShim({
		publicUrl: PUBLIC,
		gateway: "my-gateway",
		fetch: async () =>
			Response.json({
				jsonrpc: "2.0",
				id: 1,
				result: { secret: "tool output" },
			}),
		log: (entry) => {
			quiet.push(entry);
		},
	});

	test("bodies are off by default, and the response still comes through", async () => {
		const res = await shimNoBodies(
			new Request(`${PUBLIC}/mcp/my-gateway/`, {
				method: "POST",
				body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Gmail_ListEmails","arguments":{"q":"private"}}}',
			}),
		);
		expect(await res.json()).toEqual({
			jsonrpc: "2.0",
			id: 1,
			result: { secret: "tool output" },
		});
		expect(quiet[0]?.mcp_tool).toBe("Gmail_ListEmails");
		expect(quiet[0]?.request_body).toBeUndefined();
		expect(quiet[0]?.response_body).toBeUndefined();
		expect(JSON.stringify(quiet)).not.toContain("private");
	});

	test("a returned log promise goes to waitUntil", async () => {
		const waited: Promise<unknown>[] = [];
		const pending = Promise.resolve();
		const withPromise = createShim({
			publicUrl: PUBLIC,
			gateway: "my-gateway",
			log: () => pending,
		});
		await withPromise(new Request(`${PUBLIC}/nope`), {
			waitUntil: (p) => waited.push(p),
		});
		expect(waited).toEqual([pending]);
	});
});

describe("config", () => {
	test("requires the public URL and gateway", () => {
		expect(() => configFromEnv({})).toThrow(
			"missing required environment: SHIM_PUBLIC_URL, SHIM_GATEWAY",
		);
	});

	test("rejects a gateway slug that isn't one", () => {
		expect(() =>
			createShim({ publicUrl: PUBLIC, gateway: "../oauth2" }),
		).toThrow("invalid gateway slug");
	});

	test("reads optional settings", () => {
		const config = configFromEnv({
			SHIM_PUBLIC_URL: PUBLIC,
			SHIM_GATEWAY: "my-gateway",
			ARCADE_API_URL: "https://arcade.internal",
			SHIM_LOG_BODIES: "true",
			VERCEL_GIT_COMMIT_SHA: "deadbeef",
			OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector:4318",
		});
		expect(config.arcadeApiUrl).toBe("https://arcade.internal");
		expect(config.logBodies).toBe(true);
		expect(config.version).toBe("deadbeef");
		expect(typeof config.log).toBe("function");
	});

	test("a self-hosted Arcade gets its own resource", async () => {
		const seen: Request[] = [];
		const selfHosted = createShim({
			publicUrl: PUBLIC,
			gateway: "my-gateway",
			arcadeApiUrl: "https://arcade.internal/",
			arcadeAuthUrl: "https://auth.internal",
			log: () => {},
			fetch: async (req) => {
				seen.push(req);
				return Response.json({});
			},
		});
		const res = await selfHosted(
			new Request(`${PUBLIC}/oauth2/authorize?client_id=c1`),
		);
		const location = new URL(res.headers.get("location") ?? "");
		expect(location.origin).toBe("https://auth.internal");
		expect(location.searchParams.get("resource")).toBe(
			"https://arcade.internal/mcp/my-gateway",
		);
	});

	test("OTLP headers parse in the standard format", () => {
		expect(parseOtlpHeaders("dd-api-key=abc, x-other=a%3Db")).toEqual({
			"dd-api-key": "abc",
			"x-other": "a=b",
		});
	});
});

describe("headers", () => {
	const customerCredentials = {
		"ocp-apim-subscription-key": "apim-secret",
		"x-functions-key": "functions-secret",
		"x-ms-client-principal": "principal-secret",
		"x-ms-token-aad-access-token": "aad-secret",
		cookie: "session=cookie-secret",
		"x-forwarded-for": "203.0.113.9",
	};

	test("only the bearer token and MCP headers reach the gateway", async () => {
		await call("/mcp/my-gateway/", {
			method: "POST",
			headers: {
				...customerCredentials,
				authorization: `Bearer ${TOKEN}`,
				"content-type": "application/json",
				accept: "application/json, text/event-stream",
				"mcp-session-id": "s-1",
				"mcp-protocol-version": "2025-11-25",
				"last-event-id": "e-7",
			},
			body: "{}",
		});
		expect([...(upstream[0]?.headers.keys() ?? [])].sort()).toEqual([
			"accept",
			"authorization",
			"content-type",
			"last-event-id",
			"mcp-protocol-version",
			"mcp-session-id",
			"user-agent",
		]);
	});

	test("OAuth calls carry no credentials but the form's own", async () => {
		reply = () => Response.json({ access_token: "at" });
		await call("/oauth2/token", {
			method: "POST",
			headers: {
				...customerCredentials,
				authorization: "Bearer something",
				"content-type": "application/x-www-form-urlencoded",
			},
			body: "grant_type=refresh_token&refresh_token=rt&client_id=c1",
		});
		await call("/oauth2/register", {
			method: "POST",
			headers: { ...customerCredentials, "content-type": "application/json" },
			body: "{}",
		});
		for (const req of upstream) {
			expect([...req.headers.keys()].sort()).toEqual([
				"content-type",
				"user-agent",
			]);
		}
	});

	test("customer credential headers are never logged", async () => {
		await call("/mcp/my-gateway", {
			method: "POST",
			headers: {
				...customerCredentials,
				authorization: `Bearer ${TOKEN}`,
				"user-agent": "PowerPlatform",
				"x-ms-client-request-id": "req-1",
			},
			body: "{}",
		});
		const exported = JSON.stringify(otlpLogBody(logs[0] as ShimLog, "s"));
		for (const value of Object.values(customerCredentials)) {
			expect(exported).not.toContain(value);
		}
		expect(logs[0]?.headers).toEqual({
			"user-agent": "PowerPlatform",
			"x-ms-client-request-id": "req-1",
		});
	});
});

describe("limits", () => {
	test("an oversized OAuth body is refused before it reaches Arcade", async () => {
		const res = await call("/oauth2/register", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ client_name: "x".repeat(MAX_OAUTH_BODY_BYTES) }),
		});
		expect(res.status).toBe(413);
		expect(upstream).toHaveLength(0);
	});

	test("a declared length over the limit is refused without reading", async () => {
		const res = await shim(
			new Request(`${PUBLIC}/oauth2/token`, {
				method: "POST",
				headers: { "content-length": String(MAX_OAUTH_BODY_BYTES + 1) },
				body: "grant_type=refresh_token",
			}),
		);
		expect(res.status).toBe(413);
	});

	test("a streamed body is cut off at the limit", async () => {
		const small = createShim({
			publicUrl: PUBLIC,
			gateway: "my-gateway",
			maxBodyBytes: 1024,
			log: () => {},
			fetch: async () => Response.json({}),
		});
		let pulls = 0;
		const body = new ReadableStream<Uint8Array>({
			pull(controller) {
				pulls++;
				controller.enqueue(new Uint8Array(512));
				if (pulls > 100) controller.close();
			},
		});
		const res = await small(
			new Request(`${PUBLIC}/mcp/my-gateway`, {
				method: "POST",
				body,
				duplex: "half",
			} as RequestInit),
		);
		expect(res.status).toBe(413);
		expect(pulls).toBeLessThan(10);
	});

	test("readBody returns small bodies whole", async () => {
		const text = await readBody(
			new Request(PUBLIC, { method: "POST", body: "héllo" }),
			100,
		);
		expect(text).toBe("héllo");
	});
});

describe("timeouts", () => {
	/** An upstream that never answers, and records the abort. */
	const hanging = (aborted: unknown[]) => (req: Request) =>
		new Promise<Response>((_, reject) => {
			req.signal.addEventListener("abort", () => {
				aborted.push(req.signal.reason);
				reject(req.signal.reason);
			});
		});

	test("a slow OAuth endpoint is a 504", async () => {
		const aborted: unknown[] = [];
		const slow = createShim({
			publicUrl: PUBLIC,
			gateway: "my-gateway",
			oauthTimeoutMs: 20,
			log: () => {},
			fetch: hanging(aborted),
		});
		const res = await slow(
			new Request(`${PUBLIC}/oauth2/token`, { method: "POST", body: "" }),
		);
		expect(res.status).toBe(504);
		expect(aborted).toHaveLength(1);
	});

	test("a gateway that never starts answering is a 504", async () => {
		const slow = createShim({
			publicUrl: PUBLIC,
			gateway: "my-gateway",
			mcpTimeoutMs: 20,
			log: () => {},
			fetch: hanging([]),
		});
		const res = await slow(
			new Request(`${PUBLIC}/mcp/my-gateway`, { method: "POST", body: "{}" }),
		);
		expect(res.status).toBe(504);
	});

	test("an event stream outlives the timeout once it has started", async () => {
		let upstreamSignal: AbortSignal | undefined;
		const streaming = createShim({
			publicUrl: PUBLIC,
			gateway: "my-gateway",
			mcpTimeoutMs: 20,
			log: () => {},
			fetch: async (req) => {
				upstreamSignal = req.signal;
				const encoder = new TextEncoder();
				return new Response(
					new ReadableStream({
						async start(controller) {
							controller.enqueue(encoder.encode("data: 1\n\n"));
							await Bun.sleep(60);
							controller.enqueue(encoder.encode("data: 2\n\n"));
							controller.close();
						},
					}),
					{ headers: { "content-type": "text/event-stream" } },
				);
			},
		});
		const res = await streaming(
			new Request(`${PUBLIC}/mcp/my-gateway`, { method: "GET" }),
		);
		expect(await res.text()).toBe("data: 1\n\ndata: 2\n\n");
		expect(upstreamSignal?.aborted).toBe(false);
	});

	test("a client that goes away aborts the upstream call", async () => {
		const aborted: unknown[] = [];
		const slow = createShim({
			publicUrl: PUBLIC,
			gateway: "my-gateway",
			log: () => {},
			fetch: hanging(aborted),
		});
		const client = new AbortController();
		const pending = slow(
			new Request(`${PUBLIC}/mcp/my-gateway`, {
				method: "POST",
				body: "{}",
				signal: client.signal,
			}),
		);
		await Bun.sleep(5);
		client.abort();
		await pending;
		expect(aborted).toHaveLength(1);
	});

	test("timeouts and limits must be positive integers", () => {
		expect(() =>
			configFromEnv({
				SHIM_PUBLIC_URL: PUBLIC,
				SHIM_GATEWAY: "my-gateway",
				SHIM_MCP_TIMEOUT_MS: "soon",
			}),
		).toThrow("SHIM_MCP_TIMEOUT_MS must be a positive integer");
	});
});
