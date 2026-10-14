import { waitUntil } from "@vercel/functions";
import { shimFromEnv } from "../config.ts";

const shim = shimFromEnv(process.env);

export function handler(req: Request): Promise<Response> {
	return shim(req, { waitUntil });
}
