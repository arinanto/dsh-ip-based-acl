# AGENTS.md — dsh-ip-based-acl

> Project map for whoever picks this up next — a returning maintainer, another agent, or a human. It
> records what the code does, why a few unusual choices exist, and what will bite you. These are
> project conventions, not permissions: work in one reviewable step per turn, ask before adding a
> dependency or doing anything destructive, never claim unverified behavior, and never commit or push
> without an explicit yes.

## What this is

A Host-only DSH bundle (`dsh-ip-based-acl`) that gates the Harness web surface by client IP address.
Admission is **default-deny**: a client is admitted only when it matches `allow`, and a configured
reverse proxy's `X-Forwarded-For` chain may move the decision to the forwarded client.

It is **not** a web server, reverse proxy, TLS terminator, or page renderer. It does not register
routes. It hooks Connection's existing authentication entry points and refuses before any token is
exchanged.

Status at the time of writing:

- `pnpm check` green: **32 tests** (17 policy, 15 gate).
- Not installed in any live DSH profile; the bundle exists only in this checkout.
- The repository is initialized on `main`; `origin` is
  `https://github.com/arinanto/dsh-ip-based-acl.git`. Do not commit or push without an explicit yes.
- Live behavior with a real browser and a real reverse proxy is **unverified**; unit tests use stubs.

## Repo map

| Path                | Purpose                                                                                     |
| ------------------- | ------------------------------------------------------------------------------------------- |
| `src/index.ts`      | Plugin entry: `apply`, `inject: ["connection"]`, public re-exports                           |
| `src/config.ts`     | Schemastery `Config` schema and the `AclConfig` shape (`allow`, `trustedProxies`)            |
| `src/policy.ts`     | CIDR compilation, client-address resolution through XFF, allowlist decision                 |
| `src/gate.ts`       | Wraps Connection's `admit`, `authorizeIndex`, and `authorizeConnect`; writes the 403         |
| `test/`             | `node:test` suites, run against `src/` through Node's type stripping                        |
| `cordis.patch.yml`  | Bundle patch: one row, stable id `ip-based-acl`                                             |
| `locale/en.json`    | Plugin Manager title and description                                                        |
| `icon.svg`          | Hand-authored artwork: shield, `IP` monogram, pink heart                                    |
| `lib/`              | Build output (`pnpm build`); **never edit by hand**, and rebuild before installing          |
| `README.md`         | User-facing behavior, policy/proxy semantics, commands                                      |

Start here: `README.md` for semantics, then `src/gate.ts` for the request path, then `pnpm check`.

## How a request is gated

`apply` compiles the policy once, warns when `allow` is empty, and installs the gate through
`ctx.effect(() => installGate(ctx, policy), …)`. The plugin declares `inject: ["connection"]`, so a
profile without Connection (a non-Web composition) never applies it.

`installGate` wraps three methods on the **Connection service instance** — not its prototype:

| Wrapped method                | Covers                                                                                                                                       | Refusal shape                                  |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| `connection.admit`            | `/api` HTTP (including RPC and Fetch routes), the `/api/remote.mux` WebSocket through `admitConnection`, and feature routes that call `requestRejection` | returns `{ rejection: 403 }`; the caller writes the response |
| `connection.authorizeIndex`   | the SPA page, the launch-token exchange (`GET /?token=…`), and cookie-based page loads                                                       | writes `403 forbidden`, returns `false`        |
| `connection.authorizeConnect` | the API credential exchange on `/connect`                                                                                                    | writes `403 forbidden`, returns `void`         |

Every wrapper resolves the **client** address first (see Proxies), then delegates to the original
method with `.call(connection, …)` when admitted. Disposal restores all three originals.

**Why wrapping instead of a hook:** `webServer` exposes `register`, `registerUpgrade`, and one
fallback seat, with no pre-dispatch hook; Connection exposes no policy extension point. Gating just
the fallback would miss `/api` and the WebSocket mux, and registering shadow routes cannot delegate
back to the real owner. The wrapper is the narrowest seam that covers every credential-bearing path.

**Upstream contract:** verified against `@deepseek-ai/dsh-client-connection@0.2.1-rc.3`. The local
`ConnectionAuthEntry` type in `gate.ts` is structural, not imported from that package (this package
has no runtime dependency on it), so TypeScript will not catch an upstream rename. `installGate`
therefore checks `typeof` at activation and **throws** when a method is missing. Keep that
fail-loud behavior: a silent fallback to "allow" would disable the ACL.

**Coverage limits, on purpose:**

- Public asset routes (plugin bundles, HMR events) remain reachable. They carry no session data, and
  every data request behind them passes through `admit`.
- In-process peers (agent tools, workers) have no socket address and never reach the gate.
- Anything that authenticates through a new upstream entry point not wrapped here is not gated. If
  Connection grows one, add a wrapper and a test.

## Policy semantics

- `allow` is the only allowlist. A client matching no entry gets `403`, even with a valid launch token
  or a previously issued cookie.
- An **empty `allow` refuses every client, loopback included**. It logs a warning at activation. This
  is the intended default for an installed ACL, but it is also a lockout: configure `allow` in the
  same change that enables the row, or edit the profile patch and restart to recover.
- A missing or unparseable client address is refused, never treated as local.
- A bare address is a single-host rule (`203.0.113.9` is `/32`, `::1` is `/128`). CIDR networks are
  accepted in both families.
- IPv4 and IPv6 share one 128-bit space; IPv4 rules are held in mapped form, so `10.0.0.0/8` matches
  `::ffff:10.1.2.3` and either spelling of the rule works.
- A malformed pattern (bad address, bad prefix length) fails **activation**, so a typo cannot become
  a silent grant.
- Loopback must be listed explicitly. A dual-stack listener usually reports an IPv4 peer as
  `::ffff:127.0.0.1`, which the IPv4 rule covers.

## Proxy semantics (`trustedProxies`)

`clientAddress(peer, xForwardedFor, policy)` implements MDN's trusted-proxy-list method:

1. The socket peer is the only address the server observed itself. If it is **not** a trusted proxy,
   it is the client and the header is ignored entirely. A direct client cannot spoof its way in.
2. If it is trusted, read the header right to left — starting with the address the nearest proxy
   recorded — skipping every entry that is itself a trusted proxy. The first entry that is **not** a
   trusted proxy is the client. It may be an untrusted intermediate proxy rather than the origin, but
   it is the only address fit for an access decision.
3. Fallbacks: no header → the trusted peer itself; every hop trusted → the leftmost entry; a malformed
   entry is returned verbatim and therefore refused by the allowlist.

Repeated `X-Forwarded-For` headers form one list, in wire order. Entries are trimmed; blank entries
mixed with addresses fail closed.

Security rules for whoever configures it:

- `trustedProxies` must name **actual proxies you control**, never a client subnet. Any host inside a
  trusted range can forge the header.
- The proxy must **append** the peer address to the existing header, not overwrite or trust the
  client's value.
- The proxy must add `X-Forwarded-For` to the **WebSocket upgrade** too. An upgrade without it
  resolves to the proxy's own address.
- Do not put a proxy address in `allow` unless requests that resolve to the proxy (for example, a
  header-less health check) should be admitted.

Not supported (do not assume): RFC 7239 `Forwarded`, trusted-proxy-by-count, per-path proxy trust, or
proxy protocol. Add them deliberately, with tests, if a deployment needs them.

## Configuration

```yaml
- id: ip-based-acl
  config:
    allow: ["203.0.113.7", "127.0.0.1", "::1"]
    trustedProxies: ["10.0.0.1"]
```

Both fields are arrays of strings and default to `[]`. `trustedProxies: []` ignores the header. An
empty `allow` denies everyone.

Schemastery keeps unknown keys instead of rejecting them, so a leftover `deny` key would be silently
ignored. Do not reintroduce one and do not rely on it.

Override the row by id in the profile's `cordis.patch.yml`; the bundle's own patch carries no config.

## Build, test, verify

```sh
pnpm install
pnpm check     # typecheck + ESLint + Prettier + node:test
pnpm build     # rimraf lib && tsc -p tsconfig.build.json
pnpm dev       # tsc --watch
```

- Source-to-source imports use **`.ts`** specifiers so Node's type stripping can run the tests without
  a build. `tsconfig.build.json` enables `rewriteRelativeImportExtensions`, so emitted `lib/*.js`
  imports are `.js`. Declaration files keep `.ts` specifiers (DSH house style; a consumer typecheck
  resolves them).
- The test script runs `test/**/*.test.ts` directly, which needs native type stripping. The package
  declares `engines.node >= 24`, the LTS line this was developed and tested on (Node 24.22.1); older
  releases are outside the supported range even though the emitted `lib/` might run there.
- `lib/` is generated and ignored by `.gitignore`, but it is what `install_bundle` links. Rebuild after
  every source change; never patch it.
- `package.json` ships `lib`, the patch, locale files, the icon, and the README. A new runtime module
  must be reachable from `lib/`; source files are not published.
- Unit tests exercise policy and the wrappers with a **stub** Connection. There is no integration test
  against the real service or a browser. A built-package smoke test with a fake `ctx` is the quickest
  end-to-end check:

```js
import * as plugin from "./lib/index.js";
const original = { admit: () => ({ peer: "p" }), authorizeIndex: () => true, authorizeConnect: () => {} };
const connection = { ...original };
const ctx = {
  get: (name) => (name === "connection" ? connection : undefined),
  effect: (callback) => callback(),
  logger: () => ({ info() {}, warn() {} }),
};
plugin.apply(ctx, plugin.Config({ allow: ["10.0.0.0/8"] }));
console.log(connection.admit({ socket: { remoteAddress: "203.0.113.7" } })); // { rejection: 403 }
```

## Icon and display metadata

- `icon.svg` is hand-authored: the shield (unchanged from the original), a large white **IP** monogram,
  and a small pink heart (`#f9a8d4`) in the upper-right. The heart is the "Alice" mark.
- The Plugin Manager renders row icons at **30 px** (`ROW_ARTWORK_SIZE = 30`) and card/detail artwork at
  **36 px** (`CARD_ARTWORK_SIZE = 36`) in `@deepseek-ai/dsh-client-ui-plugin-manager`. Design for 30 px:
  big shapes only. The old keyhole and sparkle were removed because a second glyph cannot survive at
  that size next to an IP mark — do not re-add tiny details or small text.
- The `IP` letters are a `<text>` element with `ui-sans-serif, system-ui, sans-serif`; they render
  through the viewer's system font. Converting them to paths would make the file font-independent.
- Validate by parsing the exact file as `image/svg+xml` (no `parsererror`), then render at 30, 36, and
  ~260 px on light and dark backgrounds. Icons may be SVG/PNG/JPEG/WebP, at most 256 KiB, inside the
  package.
- Icon changes need **no build**; they appear after the bundle is installed or reloaded.

## Invariants

- Default-deny stays default-deny. No implicit loopback, no implicit proxy trust, no empty-list
  escape hatch.
- Never trust `X-Forwarded-For` unless the socket peer is in `trustedProxies`.
- Never turn a missing/unreadable address into an allow.
- Never add a fail-open path when the wrappers are unavailable; throw instead.
- Never log tokens, cookies, credentials, or full forwarded chains at info level.
- Do not gate by shadowing routes or claiming the fallback seat; the wrapper seam is deliberate.
- Do not add a runtime dependency on `@deepseek-ai/dsh-client-connection`; the structural wrapper is
  the point.
- Do not edit `lib/`, and do not install/commit/push without an explicit yes from the owner.
- Every behavior change needs a test; every semantic change updates `README.md` and this file.

## Open work

### `bypass` (planned, intentionally not started)

Requirement: a `bypass` list of IPs that are **also in `allow`**; those clients skip the launch token
entirely and receive a browser session (the same authority-bound cookie) straight away. Entries not
covered by `allow` must be rejected at activation — `bypass` narrows access, it never widens it.

Where it fits: the wrapped `authorizeIndex` receives `(request, response)` before the original token
exchange. For a bypass client with no valid cookie, mint the cookie and redirect to clean `./` the
way `BrowserAuth.authorizeIndex` does for a valid token. Be aware that `BrowserAuth` and its
`launchToken` are runtime fields on `connection.browserAuth`, not public types; the options are a
synthetic internal token exchange (never expose the launch token in a browser-visible URL) or an
upstream hook. Stub tests cannot cover cookie signing — this needs a live browser check. Do not add
the config field without the behavior, or half of it without the subset validation.

### Install and live verification

Not done yet. When it happens: build, install with `plugin_manager install_bundle` (needs approval),
configure `allow` including loopback and `trustedProxies` if proxied, then verify a denied peer gets
403 on `/`, `/api`, and the mux WebSocket; an allowed peer completes the token flow; an old cookie
does not help from a denied address; `/connect` is gated; a trusted proxy resolves the forwarded
client; and a direct client spoofing the header is refused. Restore any test state afterward.

### Other

- Consider upstreaming a policy hook in Connection so this can stop wrapping methods.
- Add an integration test if a real Connection instance can be constructed cheaply in tests.

## Commit messages

The owner enforces Conventional Commits strictly, with one house rule on top: **everything is
lowercase** — type, scope, description, and acronyms (`ip`, `dsh`, `acl`).

Use `<type>(<scope>): <description>`:

- `type` is one of `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`,
  `chore`, `revert`.
- `scope` is optional and lowercase.
- `description` is imperative, lowercase, and has no trailing period; keep the whole subject at 72
  characters or fewer.
- A body or footer is optional and follows a blank line after the subject.
- A breaking change adds `!` after the type/scope and a `BREAKING CHANGE:` (or `BREAKING-CHANGE:`)
  footer; that token keeps the spelling Conventional Commits requires, while the rest of the message
  stays lowercase.
- No co-author lines, no AI attribution.
- **Every commit is signed off (DCO).** Use `git commit --signoff` (`-s`); Git appends
  `Signed-off-by: <user.name> <user.email>` from the local config. The trailer certifies the
  [Developer Certificate of Origin 1.1](https://developercertificate.org/) claim — the author wrote the
  change or may submit it under `AGPL-3.0-only`. It is not a co-author line and not AI attribution, so
  it does not conflict with the rule above: keep it, and never sign off someone else's work.
- **First commit only:** `initial: <description>`. `initial` is not a standard Conventional type;
  the owner approved it for the initial import of this repository, and it is not used again.

Examples:

```
initial: add ip allowlist gate for the dsh web surface
feat(gate): add bypass list for trusted clients
fix(policy): reject malformed forwarded entries
docs(readme): document the trusted proxy chain
```

## Change checklist

1. Read `src/gate.ts` before touching the request path; read `src/policy.ts` before touching matching.
2. Keep the decision fail-closed and the wrappers minimal; add a test for every behavior change.
3. `pnpm check` and `pnpm build`; smoke the built package.
4. Update `README.md` (and this file when the architecture or open work changes).
5. Ask before adding dependencies, installing into the profile, or committing/pushing.

A stale map is worse than no map. If a fact here stops being true, fix it in the same change.
