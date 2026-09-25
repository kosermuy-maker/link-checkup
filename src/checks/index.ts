export { urlShapeCheck } from "./urlShape.ts";
export { lookalikeCheck, analyzeLookalike } from "./lookalike.ts";
export { rdapCheck } from "./rdap.ts";
export { dnsCheck } from "./dns.ts";
export { redirectsCheck } from "./redirects.ts";
export { tlsCheck } from "./tls.ts";
export { blocklistCheck } from "./blocklist.ts";
export { defaultDeps, type CheckContext, type CheckDeps } from "./context.ts";

import type { CheckId } from "../types.ts";

/** Order in which checks are displayed. */
export const CHECK_ORDER: CheckId[] = ["blocklist", "lookalike", "rdap", "redirects", "tls", "dns", "urlShape"];
