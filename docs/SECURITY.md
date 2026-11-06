# Security

This document is the threat model of `@trysac/rbac-abac`. Every defended claim has at least one test in `test/index.test.ts`.

## Model

The library implements hierarchical RBAC (ANSI INCITS 359) plus ABAC rules (NIST SP 800-162) under the XACML 3.0 deny-overrides algorithm. Policies are declarative JSON. Conditions are trees, never code, and are evaluated with three-valued (Kleene) logic: `true`, `false` or indeterminate.

Decision order in `evaluate`:

1. Deny rules. A true condition gives `deny-rule`; an indeterminate condition gives `deny-indeterminate`, and the rule id is reported.
2. Allow rules. Only a true condition applies.
3. Role grants, including inherited ones (`role`).
4. `default-deny`.

## Defended

| Threat | Defence |
|---|---|
| Prototype pollution and prototype-chain reads | Policy input must be plain objects; role names such as `__proto__` are rejected; ref segments may not be `__proto__`, `prototype` or `constructor`; every path step uses `Object.hasOwn`, so `resource.attributes.toString` resolves as missing. |
| Code injection | No `eval`, `Function` or string expressions. Strings in conditions are inert literals compared with `===`. Unknown operators are rejected. |
| Fail-open on missing attributes | A missing ref makes `eq`, `ne`, `in` and ordering indeterminate. An indeterminate deny rule denies; an indeterminate allow rule does not apply. `not` of indeterminate stays indeterminate. `exists` is never indeterminate. |
| Type coercion | `eq` and `ne` are strict. Ordering requires two finite numbers, otherwise the result is false. `{ eq: ["1", 1] }` is false. |
| Size exhaustion | 1000 roles, 1000 rules, inheritance depth 16, condition depth 32, 10000 condition and operand nodes per policy, `in` lists of 1000, 1000 permissions per role, 2000 distinct permissions, 1024-character strings, 256-character refs, 1000 subject roles per request. Violations throw `PolicyError` with code `limit_exceeded`. |
| CSV injection | `matrixToCsv` prefixes cells starting with `=`, `+`, `-`, `@`, tab or CR with an apostrophe and quotes cells per RFC 4180. Relevant for hand-built matrices. |
| Markdown table breakage | `matrixToMarkdown` escapes pipes and backslashes and replaces line breaks with spaces. |
| Leaking data through audit hooks | `onDecision` receives only `allowed`, `reason`, `ruleId`, `action` and `resourceType`. Hook exceptions are swallowed and never change a decision. |
| Oversized error output | Error messages and problems are clipped to 200 characters, and quoted input is clipped to 40 characters. |

## Not defended

- Wrong policies. The library enforces what the policy says, not what was intended.
- Forged caller attributes. Subject, resource and context data are trusted; the caller must authenticate and load them.
- Denial of service within the documented limits. Evaluation cost is bounded by those limits but is not rate-limited.

## Out of scope

Cedar or Rego compatibility, policy storage, resource wildcards and obligations.

## Error codes

`PolicyError.code` is one of `invalid_policy`, `inheritance_cycle`, `limit_exceeded`, `invalid_request`.
