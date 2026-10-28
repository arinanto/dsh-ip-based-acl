/**
 * Configuration for the IP-based access-control plugin.
 *
 * `allow` holds addresses or CIDR networks ("203.0.113.0/24", "::1"). They are
 * compiled when the row activates, so a malformed entry fails the plugin
 * instead of becoming a silent grant at request time.
 *
 * The list is an allowlist: a peer that matches no entry is refused, and an
 * empty `allow` therefore refuses every peer, loopback included. That is the
 * intended default for an installed ACL — an operator enables access by naming
 * the addresses that may use the web surface.
 *
 * `trustedProxies` names the reverse proxies whose `X-Forwarded-For` header may
 * be believed. The list must name only proxies you control — never a client
 * subnet, because any host inside a trusted range can forge that header. An
 * empty list ignores the header entirely and judges the socket peer.
 */

import z from "@deepseek-ai/schemastery";

/** Peer-address rules accepted by the plugin. */
export interface AclConfig {
  /** Addresses or networks allowed to reach the Harness web surface; a peer outside every entry is refused. */
  allow: string[];
  /** Addresses or networks of reverse proxies whose `X-Forwarded-For` chain is believed; empty ignores the header. */
  trustedProxies: string[];
}

/** Loader-validated schema; Cordis resolves it through the Standard Schema interface. */
export const Config = z.object({
  allow: z
    .array(String)
    .description("Addresses or CIDR networks allowed to reach the Harness web surface; every other peer is refused.")
    .default([]),
  trustedProxies: z
    .array(String)
    .description(
      "Addresses or CIDR networks of the reverse proxies whose X-Forwarded-For chain is believed; " +
        "name only proxies you control. Empty ignores the header.",
    )
    .default([]),
});
