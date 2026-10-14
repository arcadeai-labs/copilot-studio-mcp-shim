import { shimFromEnv } from "../config.ts";

const shim = shimFromEnv(process.env);
const server = Bun.serve({
	port: Number(process.env.PORT ?? 8080),
	// MCP responses can stream for a while; don't cut them off.
	idleTimeout: 255,
	fetch: (req) => shim(req),
});

console.log(
	`copilot-studio-mcp-shim for ${process.env.SHIM_GATEWAY} listening on :${server.port}`,
);
