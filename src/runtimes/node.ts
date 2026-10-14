import { serve } from "@hono/node-server";
import { shimFromEnv } from "../config.ts";

const shim = shimFromEnv(process.env);
const port = Number(process.env.PORT ?? 8080);

const server = serve({ fetch: (req) => shim(req), port }, () => {
	console.log(
		`copilot-studio-mcp-shim for ${process.env.SHIM_GATEWAY} listening on :${port}`,
	);
});

// MCP responses can stream for a while; don't cut them off.
if ("requestTimeout" in server) server.requestTimeout = 0;

for (const signal of ["SIGINT", "SIGTERM"] as const) {
	process.on(signal, () => server.close(() => process.exit(0)));
}
