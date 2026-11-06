# rbac-abac

[![npm version](https://img.shields.io/npm/v/@trysac/rbac-abac.svg)](https://www.npmjs.com/package/@trysac/rbac-abac)
[![license: MIT](https://img.shields.io/npm/l/@trysac/rbac-abac.svg)](LICENSE)
[![CI](https://github.com/Trysac/u066-rbac-abac/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u066-rbac-abac/actions/workflows/ci.yml)

Role and attribute based permission evaluator with deny-overrides, fail-closed three-valued JSON conditions, role inheritance and an exportable matrix.

## Problem

Authorization rules spread across route handlers become impossible to audit, and simple role checks cannot express rules like "owners may edit their own drafts". Policy engines that evaluate code strings add injection risk, and naive attribute checks fail open when an attribute is missing. A declarative policy with JSON conditions, one `evaluate` function and an exportable role matrix keeps permissions reviewable and safe.

## Install

```sh
npm install @trysac/rbac-abac
```

Requires Node.js 20 or newer. The package ships ES modules with TypeScript declarations.

## Usage

```ts
import { definePolicy, evaluate } from "@trysac/rbac-abac";

const when = { eq: [{ ref: "resource.attributes.status" }, "archived"] };
const rule = { id: "no-archived", effect: "deny", resource: "doc", action: "write", when } as const;
const policy = definePolicy({ roles: { editor: { permissions: ["doc:write"] } }, rules: [rule] });
const subject = { id: "u1", roles: ["editor"] };
const resource = { type: "doc", attributes: { status: "archived" } };
console.log(evaluate(policy, { subject, action: "write", resource }));
// { allowed: false, reason: 'deny-rule', ruleId: 'no-archived' }
```

## API

| Export | Signature | Description |
|---|---|---|
| `definePolicy` | `(input: PolicyInput) => Policy` | Validates, freezes and returns a policy. Copies its input. Throws `PolicyError`. |
| `evaluate` | `(policy, request, options?) => Decision` | Deny rules, then allow rules, then role grants (including inherited), then default deny. `options.onDecision` receives only `allowed`, `reason`, `ruleId`, `action` and `resourceType`. |
| `exportMatrix` | `(policy) => { roles, permissions, grants }` | Sorted matrix of effective grants after inheritance. Throws `PolicyError` for a foreign policy object. |
| `matrixToCsv` | `(matrix) => string` | RFC 4180 CSV with CRLF rows and the OWASP CSV injection guard. |
| `matrixToMarkdown` | `(matrix) => string` | Markdown table with pipes and backslashes escaped. |
| `PolicyError` | `class extends Error` | Has `code` and `problems: string[]`. |

Decision reasons: `deny-rule`, `deny-indeterminate` (an indeterminate deny condition denies and reports its `ruleId`), `allow-rule`, `role`, `default-deny`.

Error codes: `invalid_policy`, `inheritance_cycle`, `limit_exceeded`, `invalid_request`.

Role names match `^[A-Za-z][A-Za-z0-9_.-]{0,63}$`. Permissions are `resource:action` or `resource:*`. Rule ids are unique strings of at most 128 characters. Request actions and resource types match `^[a-z][a-z0-9_-]*$`. Condition operands are strings, finite numbers, booleans, `null` or `{ ref }` paths starting with `subject`, `resource`, `action` or `context`.

## Limits

1000 roles, 1000 rules, inheritance depth 16, condition depth 32, 10000 condition and operand nodes per policy, 1000 items per `in` list, 1000 permissions per role, 2000 distinct permissions per policy, 1000 subject roles per request, 1024 characters per string and 256 per ref. Violations throw `PolicyError` with code `limit_exceeded`.

## Why not Cedar or Rego

Cedar and Rego are full policy languages with their own runtimes and compatibility surfaces. This library instead keeps policies as plain JSON data validated by a small, fixed grammar. It does not read or run Cedar or Rego policies.

## Security

The threat model, including what is defended and what is not, is in [docs/SECURITY.md](docs/SECURITY.md).

## Development

```sh
npm install
npm run check   # lint, format, types, tests with coverage, docs, secrets
```

See [AGENTS.md](AGENTS.md) for the full command list and [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## License

[MIT](LICENSE) © 2026 Miguel Gomez
