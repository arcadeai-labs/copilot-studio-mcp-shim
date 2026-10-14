/**
 * Ships shim requests to an OpenTelemetry Collector (or any OTLP/HTTP JSON
 * logs endpoint, such as Datadog, Honeycomb, or Azure Monitor via a
 * collector). Fire-and-forget: a collector outage must never slow down or
 * fail an MCP call.
 */

import { consoleLog, type ShimLog } from "./shim.ts";

/** Some backends (Application Insights) truncate values at 8,192 characters. */
export const MAX_VALUE_LENGTH = 8000;

type KeyValue = { key: string; value: { stringValue: string } };

export function attributes(entry: ShimLog): KeyValue[] {
	const truncated: string[] = [];
	const attrs: KeyValue[] = [];
	for (const [key, raw] of Object.entries(entry)) {
		if (raw === undefined) continue;
		let value = typeof raw === "string" ? raw : JSON.stringify(raw);
		if (value.length > MAX_VALUE_LENGTH) {
			value = value.slice(0, MAX_VALUE_LENGTH);
			truncated.push(key);
		}
		attrs.push({ key: `shim.${key}`, value: { stringValue: value } });
	}
	if (truncated.length) {
		attrs.push({
			key: "shim.truncated",
			value: { stringValue: truncated.join(",") },
		});
	}
	return attrs;
}

export function otlpLogBody(
	entry: ShimLog,
	serviceName: string,
	now = Date.now(),
) {
	return {
		resourceLogs: [
			{
				resource: {
					attributes: [
						{ key: "service.name", value: { stringValue: serviceName } },
					],
				},
				scopeLogs: [
					{
						scope: { name: "copilot-studio-mcp-shim" },
						logRecords: [
							{
								timeUnixNano: `${BigInt(now) * 1_000_000n}`,
								severityText: entry.status >= 500 ? "ERROR" : "INFO",
								body: { stringValue: entry.event },
								attributes: attributes(entry),
							},
						],
					},
				],
			},
		],
	};
}

/** `OTEL_EXPORTER_OTLP_HEADERS` format: `key1=value1,key2=value2`. */
export function parseOtlpHeaders(
	raw: string | undefined,
): Record<string, string> {
	const out: Record<string, string> = {};
	for (const pair of (raw ?? "").split(",")) {
		const at = pair.indexOf("=");
		if (at <= 0) continue;
		out[decodeURIComponent(pair.slice(0, at).trim())] = decodeURIComponent(
			pair.slice(at + 1).trim(),
		);
	}
	return out;
}

export interface OtlpOptions {
	/** Base OTLP/HTTP endpoint, e.g. http://collector:4318. */
	endpoint: string;
	headers?: Record<string, string> | undefined;
	serviceName?: string | undefined;
}

export function otlpLogger(options: OtlpOptions) {
	const url = `${options.endpoint.replace(/\/+$/, "")}/v1/logs`;
	const serviceName = options.serviceName ?? "copilot-studio-mcp-shim";
	return (entry: ShimLog): Promise<void> => {
		consoleLog(entry);
		return fetch(url, {
			method: "POST",
			headers: { ...options.headers, "content-type": "application/json" },
			body: JSON.stringify(otlpLogBody(entry, serviceName)),
			signal: AbortSignal.timeout(2_000),
		})
			.then((res) => {
				if (!res.ok) console.error(`otlp export failed: HTTP ${res.status}`);
			})
			.catch((err: unknown) => {
				console.error(`otlp export failed: ${String(err)}`);
			});
	};
}
