/**
 * dsh-ip-based-acl — Host half of the IP-based access-control bundle.
 *
 * The row compiles its allowlist at activation and installs a gate over
 * Connection's admission, index, and connect entries: a client outside the
 * allowlist is refused before any launch token is exchanged. A client behind a
 * configured trusted proxy is resolved through `X-Forwarded-For`; a direct peer
 * is always authoritative. Peers inside the allowlist still pass through the
 * normal token and cookie flow; a future `bypass` list will mint the browser
 * session for listed peers without a token.
 *
 * The plugin is inert outside a Web composition: it injects `connection`, so a
 * profile without that service never applies the gate.
 */

import type { Context } from "@deepseek-ai/cordis";

import type { AclConfig } from "./config.ts";
import { installGate } from "./gate.ts";
import { compilePolicy } from "./policy.ts";

export { Config } from "./config.ts";
export type { AclConfig } from "./config.ts";
export { installGate, remoteAddressOf } from "./gate.ts";
export type { GateRequest, GateResponse } from "./gate.ts";
export { compilePolicy, clientAddress, isAllowed, toRule } from "./policy.ts";
export type { CidrRule, CompiledPolicy } from "./policy.ts";

/** Connection is the gate's only dependency; a non-Web profile stays inert. */
export const inject = ["connection"];

/**
 * Compile the configured allowlist and install the request gate.
 * @param ctx - Host plugin context carrying `connection`.
 * @param config - validated row configuration.
 * @throws when a configured pattern is malformed, failing the row loudly.
 */
export function apply(ctx: Context, config: AclConfig): void {
  const policy = compilePolicy(config);
  const logger = ctx.logger("ip-based-acl");
  if (policy.allow.length === 0) {
    logger.warn("allowlist is empty: every client is refused, loopback included");
  }
  ctx.effect(() => installGate(ctx, policy), "ip-based-acl: request gate");
  logger.info(
    `allowlist ready: ${String(policy.allow.length)} allow rule(s), ` +
      `${String(policy.trustedProxies.length)} trusted proxy rule(s); unlisted clients are refused`,
  );
}
