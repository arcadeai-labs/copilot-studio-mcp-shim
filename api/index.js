// Vercel entry point. `vercel.json` rewrites every path here; the shim
// routes on the original request path. Built from src/ by `npm run build`.
import { handler } from "../dist/runtimes/vercel.js";

export const GET = handler;
export const HEAD = handler;
export const POST = handler;
export const DELETE = handler;
export const OPTIONS = handler;
