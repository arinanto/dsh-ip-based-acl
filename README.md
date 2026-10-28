# dsh-ip-based-acl

A DeepSeek Harness plugin bundle that gates the Harness web surface by peer IP address.

Status: **implemented, not installed**. The allowlist is compiled at activation and installed as a
gate over Connection's admission, index, and connect entries, with `X-Forwarded-For` resolution
through configured proxies. The bundle has not been installed into a live profile, so the gate has
not yet been exercised against a running Harness.

## Policy

`allow` is an allowlist, and admission is default-deny.

- A client is admitted only when its address sits inside a configured address or CIDR network. A bare
  address is a single-host rule (`203.0.113.9` is `/32`, `::1` is `/128`).
- A client that matches no entry is refused with `403`, even when it presents a valid launch token or
  an existing session cookie.
- An empty `allow` list refuses every client, loopback included, and logs a warning at activation.
- A missing or unparseable client address is refused, never treated as local.
- A malformed pattern fails activation, so a typo cannot become a silent grant.
- IPv4 and IPv6 share one 128-bit space: `10.0.0.0/8` and `::ffff:10.0.0.0/104` describe the same
  peers, and a mapped peer matches either spelling.
- Loopback must be listed explicitly (`127.0.0.1` and/or `::1`). A dual-stack listener often reports
  an IPv4 peer in mapped form (`::ffff:127.0.0.1`), which the IPv4 rule already covers.

## Proxies

`trustedProxies` names the reverse proxies whose `X-Forwarded-For` header may be believed. The chain
is resolved with [MDN's trusted-proxy-list method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For#trusted_proxy_list):

- The socket peer is authoritative. If it is not in `trustedProxies`, it is the client and the header
  is ignored entirely — a direct client cannot spoof its way in.
- If it is, the list is read right to left, starting with the address the nearest proxy recorded and
  skipping every entry that is itself a trusted proxy. The first entry that is not one is the client.
  It may be an untrusted intermediate proxy rather than the origin, but it is the only address fit
  for an access decision.
- Repeated `X-Forwarded-For` headers form one chain. A malformed entry is treated as the client and
  therefore refused.
- Name only proxies you control, never a client subnet: any host inside a trusted range can forge the
  header. A trusted proxy that sends no header falls back to its own address, so do not list a proxy
  in `allow` unless requests resolving to it should be admitted.
- The proxy must add `X-Forwarded-For` to the WebSocket upgrade as well as to plain HTTP requests.
  An upgrade that arrives without it resolves to the proxy's own address.
- An empty `trustedProxies` ignores the header, which is the safe default for a directly exposed
  server.

```yaml
- id: ip-based-acl
  config:
    allow: ["203.0.113.7", "127.0.0.1", "::1"]
    trustedProxies: ["10.0.0.1"]
```

## Enforcement

The web carrier has no pre-dispatch hook and Connection exposes no policy extension point, so the
gate wraps the three entry points that decide whether a browser may use the interface:

| Entry point                   | Covers                                                                                                          |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `connection.admit`            | every credential-bearing request: `/api`, the Remote-stream WebSocket, and feature routes using `requestRejection` |
| `connection.authorizeIndex`   | the page itself and the launch-token exchange                                                                   |
| `connection.authorizeConnect` | the API credential exchange on `/connect`                                                                       |

An admitted peer continues through the normal token and cookie flow unchanged. A refused peer is
answered before Connection reads the credential, so no token is exchanged, no cookie is minted, and a
cookie issued earlier buys nothing. Disposal restores every original method.

Scope limits, stated plainly:

- Public asset routes (plugin bundles, HMR events) stay reachable; they carry no session data, and
  every data request behind them passes through `admit`.
- In-process peers (agent tools, workers) have no socket address and never reach the gate.
- The wrappers target the installed `@deepseek-ai/dsh-client-connection` surface (verified against
  0.2.1-rc.3). An upstream rename fails activation instead of silently dropping the gate.

A future `bypass` list — allowlisted peers that receive a browser session without a token — is not
implemented yet.

## Layout

| Path               | Purpose                                                                    |
| ------------------ | -------------------------------------------------------------------------- |
| `src/index.ts`     | Host plugin entry: `apply`, `inject`, re-exported `Config`, public seams    |
| `src/config.ts`    | `Config` schema (schemastery) and the `AclConfig` shape                    |
| `src/policy.ts`    | CIDR compilation, peer matching, and `X-Forwarded-For` resolution, framework-free |
| `src/gate.ts`      | Request-time gate over Connection's admission, index, and connect entries  |
| `test/`            | `node:test` suites run against `src/` through Node's type stripping        |
| `cordis.patch.yml` | Bundle patch: one `ip-based-acl` Host row                                  |
| `locale/en.json`   | Plugin Manager title and description                                       |
| `icon.svg`         | Original artwork exported as `./icon`                                      |
| `lib/`             | Build output (`pnpm build`); never edited by hand                          |

## Commands

```sh
pnpm install      # dependencies
pnpm check        # typecheck + lint + format check + tests
pnpm build        # emit lib/index.js and lib/types/**.d.ts
pnpm dev          # tsc --watch on the build project
```

Node 24 or newer is required; tests run `test/**/*.test.ts` through native type stripping.

`lib/` is the published shape: `main`/`types` point into it, and `install_bundle` links the package
from a checkout, so run `pnpm build` before installing the bundle into a profile.

## Style

The conventions come from the author's reference TypeScript project and are enforced by the compiler,
ESLint, and Prettier rather than by review:

- `strict` plus `noUnusedLocals`, `noUnusedParameters`, `noImplicitReturns`, `noFallthroughCasesInSwitch`,
  `noUncheckedIndexedAccess`, `noImplicitOverride`.
- Double quotes, semicolons, trailing commas everywhere, 120-column lines, 2-space indentation.
- Type-aware ESLint (`projectService`) with `@typescript-eslint/no-explicit-any` as a warning;
  `eslint-config-prettier` last so formatting stays Prettier's job.

Rules added for the Harness plugin layout:

- `erasableSyntaxOnly` — every source file must also run under Node's type stripping, which is how
  `pnpm test` executes `test/**/*.test.ts` against `src/` without a build step. No enums, namespaces,
  or parameter properties.
- `verbatimModuleSyntax` — type-only imports never leak into the emitted ESM.
- `rewriteRelativeImportExtensions` in the build project — source imports name `.ts` so the test
  runner can resolve them, and the emit rewrites them to `.js` for the published `lib/`.

## Harness contract

- The package is an ES module bundle: `dsh.bundle.patch` names `cordis.patch.yml`, whose single row
  carries the stable id `ip-based-acl`.
- The Host entry exports `apply(ctx, config)`, `Config`, and `inject: ["connection"]`; Cordis validates
  the row's `config` through the schema's Standard Schema interface before `apply` runs, and a profile
  without the `connection` service never applies the gate.
- Display metadata is exported without activating the plugin: `./locale/*.json` supplies
  `meta.title`/`meta.description`, `./icon` the artwork.
- Peer dependencies are the platform's: `@deepseek-ai/cordis` comes from the Harness install, while
  `@deepseek-ai/schemastery` is a real runtime dependency of this package.

## Verified

- `pnpm check` — typecheck, lint, formatting, and 32 policy and gate cases, including the trusted
  proxy walk, repeated headers, spoofed headers, and malformed entries.
- `pnpm build` — `lib/index.js` plus `lib/types/index.d.ts` in the layout `package.json` declares.

Not verified: installation into a live profile and the gate against a real browser session. The
unit tests exercise the wrappers with a stub Connection, not the shipped plugin.

## Contributing

Every commit must carry a [Developer Certificate of Origin](https://developercertificate.org/) sign-off,
so commit with `git commit --signoff` (`-s`). Git appends the trailer from your configured identity:

```
Signed-off-by: Your Name <you@example.com>
```

The trailer certifies the DCO 1.1 statement: you wrote the change, or you have the right to submit it
under the project's license, [AGPL-3.0-only](LICENSE). Do not type it by hand for work you did not
write, and do not drop it when rewriting or squashing commits.

## License

Copyright (C) 2026 Rinaldi Widianto

This project is licensed under the **GNU Affero General Public License, version 3 only**
(AGPL-3.0-only). The full text is in [LICENSE](LICENSE).

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Because the plugin is used over a network, section 13 applies: if you run a modified version and let
others interact with it remotely, you must offer them its corresponding source.
