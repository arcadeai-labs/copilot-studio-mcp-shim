import { type Env, shimFromEnv } from "../config.ts";
import type { ExecutionContext } from "../shim.ts";

let shim: ReturnType<typeof shimFromEnv> | undefined;

export default {
	fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		shim ??= shimFromEnv(env);
		return shim(req, ctx);
	},
};
