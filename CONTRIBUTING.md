# Contributing

Thanks for looking. This bundle is deliberately narrow: it gates the Harness web surface by peer
address and does nothing else — no TLS, no proxying, no routing. Changes that grow that scope need a
reason in the issue before they need code.

## Setup

Node 24 or newer, and pnpm (the version pinned in `package.json`). Nothing else is needed for the local
checks.

```sh
pnpm install
pnpm check     # typecheck + ESLint + Prettier + node:test
pnpm build     # emit lib/
```

`pnpm check` is also what CI runs on every push and pull request, so a green local run is the same gate
main sees.

## What a change needs

- **A test for every behavior change.** `test/` runs through `node --test` with Node's native type
  stripping, so tests need no build step.
- **`pnpm check` green, `pnpm build` run** before installing the bundle anywhere. `lib/` is generated
  and git-ignored; never edit it.
- **Docs in the same change.** `README.md` covers behavior and semantics; `AGENTS.md` covers the
  architecture, invariants, and open work. A stale map is worse than no map.
- **The gate stays default-deny and fail-closed.** No implicit loopback, no implicit proxy trust, no
  empty-list escape hatch, and no fail-open path when a wrapped method is missing — it throws instead.
  Read the invariants in `AGENTS.md` before touching `src/policy.ts` or `src/gate.ts`.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/), with everything lowercase — type, scope,
description, and acronyms. Subjects are imperative, have no trailing period, and stay within 72
characters. `AGENTS.md` has the full rule set, including breaking-change footers.

Every commit carries a [Developer Certificate of Origin](DCO) sign-off, so pass `--signoff` (`-s`):

```sh
git commit --signoff -m "fix(policy): reject malformed forwarded entries"
```

Git appends the trailer from your configured identity:

```
Signed-off-by: Your Name <you@example.com>
```

The trailer certifies the DCO 1.1 statement: you wrote the change, or you have the right to submit it
under this project's license, [AGPL-3.0-only](LICENSE). Sign off only your own work, and do not strip
the trailer when you rebase, amend, or squash.

## Reporting a way past the gate

The gate holds no secrets, so a report can be a normal issue: describe the configuration (`allow`,
`trustedProxies`), the client address, and the request that should have been refused but was not. That
setup is the whole reproduction; there is nothing to protect by using a private channel.
