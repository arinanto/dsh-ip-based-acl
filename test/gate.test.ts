import assert from "node:assert/strict";
import { test } from "node:test";

import type { Context } from "@deepseek-ai/cordis";

import type { GateRequest, GateResponse } from "../src/gate.ts";
import { installGate, remoteAddressOf } from "../src/gate.ts";
import { compilePolicy } from "../src/policy.ts";

/** One admission answer the stub connection can return. */
type Admission = { readonly peer: string } | { readonly rejection: 401 | 403 };

/** The slice of Connection the gate wraps, as a stub exposes it. */
interface StubConnection {
  admit(request: GateRequest): Admission;
  authorizeIndex(request: GateRequest, response: GateResponse): boolean;
  authorizeConnect(request: GateRequest, response: GateResponse): void;
}

interface TestResponse extends GateResponse {
  status?: number;
  headers?: Readonly<Record<string, string>>;
  body?: string;
}

function response(): TestResponse {
  const record: TestResponse = {
    status: undefined,
    headers: undefined,
    body: undefined,
    writeHead(status, headers) {
      record.status = status;
      record.headers = headers;
    },
    end(body) {
      record.body = body;
    },
  };
  return record;
}

/** Build a gate over a stub connection and capture what the stub receives. */
function fixture(allow: string[], trustedProxies: string[] = []) {
  const calls = { admit: 0, index: 0, connect: 0 };
  const last: { request?: GateRequest; response?: GateResponse } = {};

  const admit = (request: GateRequest): Admission => {
    calls.admit += 1;
    last.request = request;
    return { peer: "peer-1" };
  };
  const authorizeIndex = (request: GateRequest, response: GateResponse): boolean => {
    calls.index += 1;
    last.request = request;
    last.response = response;
    return true;
  };
  const authorizeConnect = (request: GateRequest, response: GateResponse): void => {
    calls.connect += 1;
    last.request = request;
    last.response = response;
  };
  const connection: StubConnection = { admit, authorizeIndex, authorizeConnect };

  const ctx = {
    get(name: string) {
      return name === "connection" ? connection : undefined;
    },
  } as unknown as Context;

  const dispose = installGate(ctx, compilePolicy({ allow, trustedProxies }));
  return {
    connection,
    dispose,
    calls,
    last,
    originals: { admit, authorizeIndex, authorizeConnect },
  };
}

test("reads the peer address from the server socket", () => {
  assert.equal(remoteAddressOf({ socket: { remoteAddress: "10.1.2.3" } }), "10.1.2.3");
  assert.equal(remoteAddressOf({ socket: {} }), undefined);
  assert.equal(remoteAddressOf({}), undefined);
});

test("refuses API admission for a peer outside the allowlist", () => {
  const gate = fixture(["10.0.0.0/8"]);

  assert.deepEqual(gate.connection.admit({ socket: { remoteAddress: "203.0.113.7" } }), { rejection: 403 });
  assert.equal(gate.calls.admit, 0);
  gate.dispose();
});

test("delegates API admission for an allowlisted peer", () => {
  const gate = fixture(["10.0.0.0/8"]);
  const req = { socket: { remoteAddress: "10.1.2.3" } };

  assert.deepEqual(gate.connection.admit(req), { peer: "peer-1" });
  assert.equal(gate.calls.admit, 1);
  assert.equal(gate.last.request, req);
  gate.dispose();
});

test("denies a direct client that spoofs the forwarded header", () => {
  const gate = fixture(["203.0.113.7"], ["10.0.0.1"]);

  const admission = gate.connection.admit({
    socket: { remoteAddress: "198.51.100.9" },
    headers: { "x-forwarded-for": "203.0.113.7" },
  });
  assert.deepEqual(admission, { rejection: 403 });
  assert.equal(gate.calls.admit, 0);
  gate.dispose();
});

test("admits the client forwarded by a trusted proxy", () => {
  const gate = fixture(["203.0.113.7"], ["10.0.0.1"]);

  const admission = gate.connection.admit({
    socket: { remoteAddress: "10.0.0.1" },
    headers: { "x-forwarded-for": "203.0.113.7" },
  });
  assert.deepEqual(admission, { peer: "peer-1" });
  assert.equal(gate.calls.admit, 1);
  gate.dispose();
});

test("resolves the client through a chain of trusted proxies", () => {
  const gate = fixture(["203.0.113.7"], ["10.0.0.0/8"]);

  const admission = gate.connection.admit({
    socket: { remoteAddress: "10.0.0.9" },
    headers: { "x-forwarded-for": "spoofed, 203.0.113.7, 10.0.0.8" },
  });
  assert.deepEqual(admission, { peer: "peer-1" });
  gate.dispose();
});

test("refuses the index for a forwarded client outside the allowlist", () => {
  const gate = fixture(["203.0.113.7"], ["10.0.0.1"]);
  const res = response();

  const allowed = gate.connection.authorizeIndex(
    { socket: { remoteAddress: "10.0.0.1" }, headers: { "x-forwarded-for": "198.51.100.9" } },
    res,
  );
  assert.equal(allowed, false);
  assert.equal(res.status, 403);
  gate.dispose();
});

test("serves the index for a forwarded client inside the allowlist", () => {
  const gate = fixture(["203.0.113.7"], ["10.0.0.1"]);
  const res = response();

  const allowed = gate.connection.authorizeIndex(
    { socket: { remoteAddress: "10.0.0.1" }, headers: { "x-forwarded-for": "203.0.113.7" } },
    res,
  );
  assert.equal(allowed, true);
  assert.equal(gate.calls.index, 1);
  gate.dispose();
});

test("refuses the index for a peer outside the allowlist", () => {
  const gate = fixture(["10.0.0.0/8"]);
  const res = response();
  const allowed = gate.connection.authorizeIndex({ socket: { remoteAddress: "203.0.113.7" } }, res);

  assert.equal(allowed, false);
  assert.equal(res.status, 403);
  assert.equal(res.body, "forbidden");
  assert.equal(gate.calls.index, 0);
  gate.dispose();
});

test("delegates the index for an allowlisted peer", () => {
  const gate = fixture(["10.0.0.0/8"]);
  const req = { socket: { remoteAddress: "10.1.2.3" } };
  const res = response();

  assert.equal(gate.connection.authorizeIndex(req, res), true);
  assert.equal(gate.calls.index, 1);
  assert.equal(gate.last.request, req);
  assert.equal(gate.last.response, res);
  assert.equal(res.status, undefined);
  gate.dispose();
});

test("matches an IPv4-mapped peer against an IPv4 rule", () => {
  const gate = fixture(["10.0.0.0/8"]);
  const res = response();

  assert.equal(gate.connection.authorizeIndex({ socket: { remoteAddress: "::ffff:10.1.2.3" } }, res), true);
  assert.equal(gate.calls.index, 1);
  gate.dispose();
});

test("refuses the API credential exchange for a peer outside the allowlist", () => {
  const gate = fixture(["10.0.0.0/8"]);
  const res = response();

  gate.connection.authorizeConnect({ socket: { remoteAddress: "198.51.100.9" } }, res);
  assert.equal(res.status, 403);
  assert.equal(gate.calls.connect, 0);
  gate.dispose();
});

test("delegates the API credential exchange for an allowlisted peer", () => {
  const gate = fixture(["10.0.0.0/8"]);
  const req = { socket: { remoteAddress: "10.1.2.3" } };
  const res = response();

  gate.connection.authorizeConnect(req, res);
  assert.equal(gate.calls.connect, 1);
  assert.equal(gate.last.request, req);
  assert.equal(res.status, undefined);
  gate.dispose();
});

test("refuses a request whose carrier reports no peer address", () => {
  const gate = fixture(["0.0.0.0/0"]);
  const res = response();

  assert.deepEqual(gate.connection.admit({}), { rejection: 403 });
  assert.equal(gate.connection.authorizeIndex({}, res), false);
  assert.equal(res.status, 403);
  assert.equal(gate.calls.admit, 0);
  assert.equal(gate.calls.index, 0);
  gate.dispose();
});

test("disposal restores the original entries", () => {
  const gate = fixture([]);
  assert.notEqual(gate.connection.admit, gate.originals.admit);
  assert.notEqual(gate.connection.authorizeIndex, gate.originals.authorizeIndex);
  assert.notEqual(gate.connection.authorizeConnect, gate.originals.authorizeConnect);

  gate.dispose();
  assert.equal(gate.connection.admit, gate.originals.admit);
  assert.equal(gate.connection.authorizeIndex, gate.originals.authorizeIndex);
  assert.equal(gate.connection.authorizeConnect, gate.originals.authorizeConnect);
});
