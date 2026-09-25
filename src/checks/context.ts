import type { NormalizedUrl } from "../types.ts";
import { headOnlyRequest, tlsHandshake, type HeadResult, type SafeRequestOptions, type TlsInfo } from "../net/safeRequest.ts";
import { fetchLimited, type LimitedFetchOptions, type LimitedResponse } from "../net/limitedFetch.ts";
import { loadBlocklists, type Blocklists } from "./blocklistData.ts";

/** Network functions are injected so unit tests never touch the network. */
export interface CheckDeps {
  headRequest: (url: string, opts?: SafeRequestOptions) => Promise<HeadResult>;
  tlsHandshake: (host: string, opts?: SafeRequestOptions & { port?: number }) => Promise<TlsInfo>;
  fetchText: (url: string, opts?: LimitedFetchOptions) => Promise<LimitedResponse>;
  loadBlocklists: (signal?: AbortSignal) => Promise<Blocklists>;
}

export interface CheckContext {
  target: NormalizedUrl;
  now: Date;
  offline: boolean;
  deps: CheckDeps;
  signal?: AbortSignal;
}

export const defaultDeps: CheckDeps = {
  headRequest: headOnlyRequest,
  tlsHandshake,
  fetchText: fetchLimited,
  loadBlocklists,
};
