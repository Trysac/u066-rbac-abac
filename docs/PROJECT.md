# Project record: rbac-abac

## Objective

Provide a declarative, reviewable permission evaluator for Node.js that combines hierarchical role grants with JSON attribute rules. Conditions use three-valued logic so a missing attribute never produces an allow, and the effective role matrix can be exported for review. Intended for application developers who need to express rules such as owners editing their own drafts without writing code strings.

## Scope

In scope:

- The public API documented in the README: `definePolicy`, `evaluate`, `exportMatrix`, `matrixToCsv`, `matrixToMarkdown` and `PolicyError`.
- Hierarchical RBAC with role inheritance and `resource:action` or `resource:*` permissions.
- ABAC rules with allow and deny effects and JSON condition trees.
- Deny-overrides resolution with indeterminate deny conditions yielding deny.
- CSV and Markdown rendering of role matrices.

Out of scope:

- Cedar or Rego compatibility.
- Policy storage, loading or distribution.
- Resource wildcards.
- Obligations and advice.
- Authentication and trustworthy retrieval of subject, resource or context attributes.

## Timeline

| Date | Milestone |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only. Leave "pending measurement" until a real figure is recorded; never estimate here.

| Metric | Value | Source |
|---|---|---|
| Tokens (input / output) | 327995 / 108479 | factory ledger |
| Hours (human) | pending measurement | time log |
| Cost (USD) | 0.7603 | factory ledger |

## Factory run u066 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2512 | 91388 | 0 | 4473 | 0.4599 |
| fix-1 | claude-sonnet-5-5 | no | 6 | 585 | 7058 | 41790 | 0.0277 |
| fix-2 | claude-sonnet-5-5 | no | 12 | 2797 | 9104 | 90843 | 0.0598 |
| audit | claude-sonnet-5-5 | no | 10 | 4075 | 45210 | 109127 | 0.1647 |
| fix-3 | claude-sonnet-5-5 | no | 6 | 1626 | 8007 | 40640 | 0.0404 |
| docs | claude-haiku-5-5 | no | 38576 | 8008 | 0 | 0 | 0.0079 |

Total: $0.7603. Prices: Anthropic list prices.
