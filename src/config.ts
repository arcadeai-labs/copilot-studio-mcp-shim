import { otlpLogger, parseOtlpHeaders } from "./otlp.ts";
import { createShim, type ShimConfig } from "./shim.ts";

export type Env = Record<string, string | undefined>;

const TRUE = new Set(["1", "true", "yes", "on"]);

/** The commit a host built from, for the platforms that expose one. */
function detectVersion(env: Env): string | undefined {
	return (
		env.SHIM_VERSION ??
		env.VERCEL_GIT_COMMIT_SHA ??
		env.RENDER_GIT_COMMIT ??
		env.CF_PAGES_COMMIT_SHA ??
		env.SOURCE_VERSION ??
		env.GIT_COMMIT
	);
}

function positiveInt(env: Env, name: string): number | undefined {
	const raw = env[name];
	if (raw === undefined || raw === "") return undefined;
	const value = Number(raw);
	if (!Number.isInteger(value) || value <= 0) {
		throw new Error(
			`${name} must be a positive integer, got ${JSON.stringify(raw)}`,
		);
	}
	return value;
}

/** Shim settings from environment variables. See the README for each one. */
export function configFromEnv(env: Env): ShimConfig {
	const publicUrl = env.SHIM_PUBLIC_URL;
	const gateway = env.SHIM_GATEWAY;
	const missing = [
		...(publicUrl ? [] : ["SHIM_PUBLIC_URL"]),
		...(gateway ? [] : ["SHIM_GATEWAY"]),
	];
	if (!publicUrl || !gateway) {
		throw new Error(`missing required environment: ${missing.join(", ")}`);
	}
	const endpoint = env.OTEL_EXPORTER_OTLP_ENDPOINT;
	return {
		publicUrl,
		gateway,
		arcadeApiUrl: env.ARCADE_API_URL,
		arcadeAuthUrl: env.ARCADE_AUTH_URL,
		logBodies: TRUE.has((env.SHIM_LOG_BODIES ?? "").toLowerCase()),
		maxBodyBytes: positiveInt(env, "SHIM_MAX_BODY_BYTES"),
		oauthTimeoutMs: positiveInt(env, "SHIM_OAUTH_TIMEOUT_MS"),
		mcpTimeoutMs: positiveInt(env, "SHIM_MCP_TIMEOUT_MS"),
		version: detectVersion(env),
		...(endpoint
			? {
					log: otlpLogger({
						endpoint,
						headers: parseOtlpHeaders(env.OTEL_EXPORTER_OTLP_HEADERS),
						serviceName: env.OTEL_SERVICE_NAME,
					}),
				}
			: {}),
	};
}

export function shimFromEnv(env: Env) {
	return createShim(configFromEnv(env));
}
