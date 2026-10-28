import assert from "node:assert/strict";
import { test } from "node:test";

import { clientAddress, compilePolicy, isAllowed } from "../src/policy.ts";

function policyOf(allow: string[], trustedProxies: string[] = []) {
  return compilePolicy({ allow, trustedProxies });
}

test("an empty allowlist refuses every peer", () => {
  const policy = policyOf([]);
  assert.equal(isAllowed("203.0.113.7", policy), false);
  assert.equal(isAllowed("::1", policy), false);
  assert.equal(isAllowed("127.0.0.1", policy), false);
});

test("allows a peer inside an IPv4 network and refuses one outside it", () => {
  const policy = policyOf(["10.0.0.0/8"]);
  assert.equal(isAllowed("10.4.5.6", policy), true);
  assert.equal(isAllowed("11.4.5.6", policy), false);
});

test("treats a bare address as a single-host rule", () => {
  const policy = policyOf(["203.0.113.9"]);
  assert.equal(isAllowed("203.0.113.9", policy), true);
  assert.equal(isAllowed("203.0.113.10", policy), false);
});

test("lets a default route admit every peer of its own family only", () => {
  const policy = policyOf(["0.0.0.0/0"]);
  assert.equal(isAllowed("198.51.100.9", policy), true);
  assert.equal(isAllowed("2001:db8::5", policy), false);
});

test("matches an IPv4-mapped IPv6 peer against an IPv4 rule", () => {
  const policy = policyOf(["10.0.0.0/8"]);
  assert.equal(isAllowed("::ffff:10.1.2.3", policy), true);
  assert.equal(isAllowed("::ffff:192.0.2.1", policy), false);
});

test("matches an IPv6 network without crossing families", () => {
  const policy = policyOf(["2001:db8::/32"]);
  assert.equal(isAllowed("2001:db8:1::5", policy), true);
  assert.equal(isAllowed("2001:db9::5", policy), false);
  assert.equal(isAllowed("10.0.0.1", policy), false);
});

test("refuses a peer address it cannot read", () => {
  const policy = policyOf(["0.0.0.0/0"]);
  assert.equal(isAllowed(undefined, policy), false);
  assert.equal(isAllowed("not-an-ip", policy), false);
});

test("rejects a malformed pattern instead of guessing", () => {
  assert.throws(() => policyOf(["10.0.0.0/33"]), /10\.0\.0\.0\/33/u);
  assert.throws(() => policyOf(["10.0.0.0/"]), /10\.0\.0\.0\//u);
  assert.throws(() => policyOf(["10.0.0.0.0"]), /10\.0\.0\.0\.0/u);
  assert.throws(() => policyOf([], ["10.0.0.0/33"]), /10\.0\.0\.0\/33/u);
});

test("ignores the forwarded header when the peer is not a trusted proxy", () => {
  const policy = policyOf(["203.0.113.7"], ["10.0.0.1"]);
  assert.equal(clientAddress("198.51.100.9", "203.0.113.7", policy), "198.51.100.9");
  assert.equal(isAllowed(clientAddress("198.51.100.9", "203.0.113.7", policy), policy), false);
});

test("resolves the client recorded by a trusted proxy", () => {
  const policy = policyOf(["203.0.113.7"], ["10.0.0.1"]);
  assert.equal(clientAddress("10.0.0.1", "203.0.113.7", policy), "203.0.113.7");
  assert.equal(isAllowed(clientAddress("10.0.0.1", "203.0.113.7", policy), policy), true);
});

test("walks the chain right to left past trusted proxies", () => {
  const policy = policyOf(["203.0.113.7"], ["10.0.0.0/8"]);
  assert.equal(clientAddress("10.0.0.9", "spoofed, 203.0.113.7, 10.0.0.8", policy), "203.0.113.7");
});

test("stops at the first untrusted hop from the right", () => {
  const policy = policyOf([], ["10.0.0.0/8"]);
  assert.equal(clientAddress("10.0.0.1", "203.0.113.7, 198.51.100.9", policy), "198.51.100.9");
});

test("takes the leftmost entry when every hop is a trusted proxy", () => {
  const policy = policyOf([], ["10.0.0.0/8"]);
  assert.equal(clientAddress("10.0.0.1", "10.0.0.2, 10.0.0.3", policy), "10.0.0.2");
});

test("joins repeated forwarded headers into one chain", () => {
  const policy = policyOf([], ["10.0.0.0/8"]);
  assert.equal(clientAddress("10.0.0.1", ["203.0.113.7", "10.0.0.2"], policy), "203.0.113.7");
});

test("treats a malformed forwarded entry as the client and refuses it", () => {
  const policy = policyOf(["0.0.0.0/0"], ["10.0.0.0/8"]);
  assert.equal(clientAddress("10.0.0.1", "not-an-ip", policy), "not-an-ip");
  assert.equal(isAllowed(clientAddress("10.0.0.1", "not-an-ip", policy), policy), false);
});

test("falls back to the trusted peer when no header is sent", () => {
  const policy = policyOf([], ["10.0.0.0/8"]);
  assert.equal(clientAddress("10.0.0.1", undefined, policy), "10.0.0.1");
  assert.equal(clientAddress("10.0.0.1", "  ", policy), "10.0.0.1");
});

test("matches a mapped trusted proxy against an IPv4 rule", () => {
  const policy = policyOf([], ["10.0.0.0/8"]);
  assert.equal(clientAddress("::ffff:10.0.0.1", "::ffff:203.0.113.7", policy), "::ffff:203.0.113.7");
});
