/**
 * Peer-address policy: compile configured allowlist and trusted-proxy patterns
 * into 128-bit rules, resolve the client address of one request, and test it.
 *
 * The list is an allowlist, not a denylist. A peer is admitted only when it
 * matches a configured rule, so an empty list refuses every peer, and an
 * address the carrier cannot report is refused before any rule is consulted.
 * The gate this project builds is only as trustworthy as this matcher, so a
 * malformed pattern fails when the plugin activates, never mid-request.
 *
 * `X-Forwarded-For` is believed only as far as the trusted-proxy chain
 * justifies it: a direct peer is always authoritative, and behind proxies the
 * header is walked from its right end, skipping trusted proxies, until the
 * first address that is not one — MDN's trusted-proxy-list method.
 *
 * Both families compare in one 128-bit space: IPv4 rules and IPv4 peers are held
 * in their IPv4-mapped IPv6 form, so "10.0.0.0/8" and "::ffff:10.0.0.0/104"
 * describe the same peers and a mapped peer matches either spelling.
 */

import { isIPv4, isIPv6 } from "node:net";

import type { AclConfig } from "./config.ts";

/** One compiled rule: a network address and how many leading bits it fixes. */
export interface CidrRule {
  /** Network address in the 128-bit space, masked to `prefixLength`. */
  readonly network: bigint;
  /** Leading bits that must match; IPv4 rules carry the mapped-prefix offset. */
  readonly prefixLength: number;
}

/** Compiled allowlist and trusted-proxy rules, ready for request-time comparison. */
export interface CompiledPolicy {
  readonly allow: readonly CidrRule[];
  readonly trustedProxies: readonly CidrRule[];
}

const ADDRESS_BITS = 128n;
const FULL_MASK = (1n << ADDRESS_BITS) - 1n;
const IPV4_BITS = 32;
const IPV6_BITS = 128;
const IPV6_GROUPS = IPV6_BITS / 16;
const IPV4_MAPPED_OFFSET = 96;
const IPV4_MAPPED_BASE = 0xffffn << 32n;
const PREFIX_DIGITS = /^\d{1,3}$/u;

/** Leading-bits mask in the 128-bit space: prefix 0 fixes nothing, 128 everything. */
function maskFor(prefixLength: number): bigint {
  const trailingBits = ADDRESS_BITS - BigInt(prefixLength);
  return FULL_MASK ^ ((1n << trailingBits) - 1n);
}

/** Numeric value of a dotted-quad address; callers pass text `isIPv4` already accepted. */
function ipv4Value(address: string): bigint {
  return address.split(".").reduce((value, octet) => (value << 8n) | BigInt(octet), 0n);
}

/** One IPv6 group as 16-bit values; an embedded dotted quad occupies two groups. */
function groupValues(group: string): bigint[] {
  if (isIPv4(group)) {
    const value = ipv4Value(group);
    return [value >> 16n, value & 0xffffn];
  }
  return [BigInt(`0x${group}`)];
}

/** Group values of an IPv6 address, expanding `::` to the missing zero groups. */
function ipv6Groups(address: string): bigint[] {
  const compression = address.indexOf("::");
  if (compression === -1) {
    return address.split(":").flatMap(groupValues);
  }
  const head = address.slice(0, compression);
  const tail = address.slice(compression + 2);
  const leading = head === "" ? [] : head.split(":").flatMap(groupValues);
  const trailing = tail === "" ? [] : tail.split(":").flatMap(groupValues);
  const zeros = Math.max(IPV6_GROUPS - leading.length - trailing.length, 0);
  return [...leading, ...Array<bigint>(zeros).fill(0n), ...trailing];
}

/** Numeric value of an IPv6 address, tolerating a zone id on link-local text. */
function ipv6Value(address: string): bigint {
  const zone = address.indexOf("%");
  const text = zone === -1 ? address : address.slice(0, zone);
  return ipv6Groups(text).reduce((value, group) => (value << 16n) | group, 0n);
}

/** 128-bit form of a peer address, or undefined when it is missing or not an address. */
function addressValue(address: string | undefined): bigint | undefined {
  if (address === undefined) {
    return undefined;
  }
  const zone = address.indexOf("%");
  const text = zone === -1 ? address : address.slice(0, zone);
  if (isIPv4(text)) {
    return IPV4_MAPPED_BASE | ipv4Value(text);
  }
  if (isIPv6(text)) {
    return ipv6Value(text);
  }
  return undefined;
}

/** Whether one peer value sits inside one compiled rule. */
function matches(rule: CidrRule, address: bigint): boolean {
  return (address & maskFor(rule.prefixLength)) === rule.network;
}

/** Whether one address text sits inside any rule; unreadable text never matches. */
function matchesAny(address: string | undefined, rules: readonly CidrRule[]): boolean {
  const value = addressValue(address);
  return value !== undefined && rules.some((rule) => matches(rule, value));
}

/**
 * Compile one configured pattern into a rule.
 *
 * A bare address is a single-host rule ("10.1.2.3" is /32, "::1" is /128).
 *
 * @param pattern - address or CIDR network, IPv4 or IPv6.
 * @returns the masked rule in the shared 128-bit space.
 * @throws when the text is not an address, or its prefix length is outside the family.
 */
export function toRule(pattern: string): CidrRule {
  const text = pattern.trim();
  const slash = text.indexOf("/");
  const addressText = slash === -1 ? text : text.slice(0, slash);
  const prefixText = slash === -1 ? undefined : text.slice(slash + 1);

  const familyBits = isIPv4(addressText) ? IPV4_BITS : isIPv6(addressText) ? IPV6_BITS : 0;
  if (familyBits === 0) {
    throw new Error(`ip-based-acl: ${JSON.stringify(pattern)} is not an IP address or CIDR network`);
  }
  if (prefixText !== undefined && !PREFIX_DIGITS.test(prefixText)) {
    throw new Error(`ip-based-acl: ${JSON.stringify(pattern)} has a malformed prefix length`);
  }

  const prefixLength = prefixText === undefined ? familyBits : Number(prefixText);
  if (prefixLength > familyBits) {
    throw new Error(`ip-based-acl: ${JSON.stringify(pattern)} has a prefix length outside 0-${String(familyBits)}`);
  }

  const network = familyBits === IPV4_BITS ? IPV4_MAPPED_BASE | ipv4Value(addressText) : ipv6Value(addressText);
  const addressBits = familyBits === IPV4_BITS ? prefixLength + IPV4_MAPPED_OFFSET : prefixLength;
  return { network: network & maskFor(addressBits), prefixLength: addressBits };
}

/**
 * Compile the configured allowlist and trusted-proxy lists, failing on the
 * first malformed entry.
 * @param config - validated plugin configuration.
 * @returns the policy request-time checks use.
 */
export function compilePolicy(config: AclConfig): CompiledPolicy {
  return {
    allow: config.allow.map((pattern) => toRule(pattern)),
    trustedProxies: config.trustedProxies.map((pattern) => toRule(pattern)),
  };
}

/**
 * Decide one address against the compiled allowlist.
 *
 * Admission is default-deny: only an address that matches an allowlist rule
 * passes. A missing or unparseable address is refused, so a request without a
 * readable peer address cannot become a free pass, and an empty allowlist
 * refuses every address. Callers pass the address returned by
 * {@link clientAddress}, not the raw socket peer, when proxies are trusted.
 *
 * @param remoteAddress - client address to judge.
 * @param policy - compiled rules.
 * @returns true only when the address matches a compiled allowlist rule.
 */
export function isAllowed(remoteAddress: string | undefined, policy: CompiledPolicy): boolean {
  return matchesAny(remoteAddress, policy.allow);
}

/**
 * Every address entry of an `X-Forwarded-For` header value, in wire order.
 *
 * Repeated headers form one list (MDN: join them or concatenate their lists,
 * never read only one). A blank value yields no entries; blank entries mixed
 * with addresses are kept so they become a non-matching client and fail closed.
 */
function forwardedEntries(forwardedFor: string | readonly string[] | undefined): string[] {
  if (forwardedFor === undefined) {
    return [];
  }
  const values = typeof forwardedFor === "string" ? [forwardedFor] : forwardedFor;
  const entries = values.flatMap((value) => value.split(",")).map((entry) => entry.trim());
  return entries.some((entry) => entry !== "") ? entries : [];
}

/**
 * Resolve the client address of one request through its trusted-proxy chain.
 *
 * The socket peer is the only address this server observed itself. When that
 * peer is not a configured trusted proxy, it is the client and any
 * `X-Forwarded-For` header is ignored: a directly connected client can write
 * whatever it likes there.
 *
 * When the peer is trusted, the header list is searched from its right end —
 * the address the nearest proxy recorded — skipping every entry that is itself
 * a trusted proxy. The first entry that is not one is the client. It may be an
 * untrusted intermediate proxy rather than the origin, but it is the only
 * address fit for an access decision (MDN's trusted-proxy-list method).
 *
 * A trusted proxy that sends no header falls back to its own address, and a
 * chain made entirely of trusted proxies resolves to its leftmost entry. A
 * malformed entry is returned verbatim, so the allowlist refuses it.
 *
 * @param peerAddress - socket peer address, as `node:net` reports it.
 * @param forwardedFor - one header value or the repeated-header list.
 * @param policy - compiled allowlist and trusted-proxy rules.
 * @returns the address the allowlist must judge, or undefined when the peer is unreadable.
 */
export function clientAddress(
  peerAddress: string | undefined,
  forwardedFor: string | readonly string[] | undefined,
  policy: CompiledPolicy,
): string | undefined {
  if (!matchesAny(peerAddress, policy.trustedProxies)) {
    return peerAddress;
  }
  const entries = forwardedEntries(forwardedFor);
  let candidate = peerAddress;
  for (let index = entries.length - 1; index >= 0; index -= 1) {
    const entry = entries[index];
    if (entry === undefined) {
      continue;
    }
    if (!matchesAny(entry, policy.trustedProxies)) {
      return entry;
    }
    candidate = entry;
  }
  return candidate;
}
