import { serve } from "@hono/node-server";
import { shimFromEnv } from "../config.ts";

const shim = shimFromEnv(process.env);
const port = Number(process.env.PORT ?? 8080);

// Bound how long a client may take to send its request, so slow uploads
// can't hold connections open. These don't limit how long a response
// streams back, so MCP event streams are unaffected. Node only enforces
// them every `connectionsCheckingInterval`, so check often.
const server = serve(
	{
		fetch: (req) => shim(req),
		port,
		serverOptions: {
			headersTimeout: 15_000,
			requestTimeout: 30_000,
			connectionsCheckingInterval: 2_000,
		},
	},
	() => {
		console.log(
			`copilot-studio-mcp-shim for ${process.env.SHIM_GATEWAY} listening on :${port}`,
		);
	},
);

for (const signal of ["SIGINT", "SIGTERM"] as const) {
	process.on(signal, () => server.close(() => process.exit(0)));
}
