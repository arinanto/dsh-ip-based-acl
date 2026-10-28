/**
 * Request-time enforcement of the allowlist.
 *
 * The web carrier offers no pre-dispatch hook and Connection offers no policy
 * extension point, so the gate wraps the three request entry points that decide
 * whether a browser may use the interface:
 *
 * - `connection.admit` — every credential-bearing request: the `/api` route,
 *   the Remote-stream WebSocket upgrade, and any feature route that asks
 *   `requestRejection` before serving;
 * - `connection.authorizeIndex` — the page itself and the launch-token exchange;
 * - `connection.authorizeConnect` — the API credential exchange on `/connect`.
 *
 * A denied peer is answered 403 before Connection reads the credential, so no
 * token is exchanged, no cookie is minted, and a cookie issued earlier buys
 * nothing. Each wrapper delegates to the original method for an admitted peer,
 * and disposal restores every original method.
 *
 * Public asset routes (plugin bundles, HMR events) stay reachable: they carry no
 * session data, and every data request behind them passes through `admit`.
 * In-process peers have no socket address and never reach this gate. The
 * wrappers target the installed `@deepseek-ai/dsh-client-connection` surface
 * (verified against 0.2.1-rc.3); an upstream rename fails activation instead of
 * silently dropping the gate.
 */

import type { Context } from "@deepseek-ai/cordis";

import type { CompiledPolicy } from "./policy.ts";
import { clientAddress, isAllowed } from "./policy.ts";

/** The slice of a Node request the gate reads: its server socket and headers. */
export interface GateRequest {
  readonly socket?: { readonly remoteAddress?: string | undefined } | undefined;
  readonly headers?: Readonly<Record<string, string | readonly string[] | undefined>> | undefined;
}

/** The response operations the gate writes a refusal with. */
export interface GateResponse {
  writeHead(status: number, headers?: Readonly<Record<string, string>>): unknown;
  end(body?: string): unknown;
}

/** Admission of one credential-bearing request: the peer it speaks for, or the refusal. */
type PeerAdmission = { readonly peer: unknown } | { readonly rejection: 401 | 403 };

/** The Connection methods the gate wraps, as the installed package exposes them. */
interface ConnectionAuthEntry {
  admit(request: GateRequest): PeerAdmission;
  authorizeIndex(request: GateRequest, response: GateResponse): boolean;
  authorizeConnect(request: GateRequest, response: GateResponse): void;
}

/**
 * Peer address of one request, or undefined when the carrier reports none.
 * @param request - request carrying the server socket.
 * @returns the address text `node:net` reports, including IPv4-mapped forms.
 */
export function remoteAddressOf(request: GateRequest): string | undefined {
  return request.socket?.remoteAddress;
}

/** Answer a refused peer before any token, cookie, or credential is touched. */
function refuse(response: GateResponse): void {
  response.writeHead(403, { "cache-control": "no-store", "content-type": "text/plain; charset=utf-8" });
  response.end("forbidden");
}

/** Whether the request's resolved client address falls outside the allowlist. */
function isDenied(request: GateRequest, policy: CompiledPolicy): boolean {
  const client = clientAddress(remoteAddressOf(request), request.headers?.["x-forwarded-for"], policy);
  return !isAllowed(client, policy);
}

/**
 * Wrap Connection's request entry points with the allowlist.
 * @param ctx - Host context carrying `connection`.
 * @param policy - compiled allowlist.
 * @returns the disposer restoring every original method.
 * @throws when the `connection` service is missing or no longer exposes the
 *   entry points this gate wraps.
 */
export function installGate(ctx: Context, policy: CompiledPolicy): () => void {
  const connection = ctx.get("connection") as ConnectionAuthEntry | undefined;
  if (connection === undefined) {
    throw new Error("ip-based-acl: the connection service is required to install the request gate");
  }
  const admit = connection.admit;
  const authorizeIndex = connection.authorizeIndex;
  const authorizeConnect = connection.authorizeConnect;
  if (typeof admit !== "function" || typeof authorizeIndex !== "function" || typeof authorizeConnect !== "function") {
    throw new Error("ip-based-acl: the installed connection service does not expose the entry points this gate wraps");
  }

  function guardedAdmit(request: GateRequest): PeerAdmission {
    if (isDenied(request, policy)) {
      return { rejection: 403 };
    }
    return admit.call(connection, request);
  }

  function guardedIndex(request: GateRequest, response: GateResponse): boolean {
    if (isDenied(request, policy)) {
      refuse(response);
      return false;
    }
    return authorizeIndex.call(connection, request, response);
  }

  function guardedConnect(request: GateRequest, response: GateResponse): void {
    if (isDenied(request, policy)) {
      refuse(response);
      return;
    }
    authorizeConnect.call(connection, request, response);
  }

  connection.admit = guardedAdmit;
  connection.authorizeIndex = guardedIndex;
  connection.authorizeConnect = guardedConnect;

  return () => {
    connection.admit = admit;
    connection.authorizeIndex = authorizeIndex;
    connection.authorizeConnect = authorizeConnect;
  };
}
