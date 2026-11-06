# Fail-closed three-valued evaluation under deny-overrides

Status: accepted (generated, pending human review)

## Context

Authorization rules scattered across handlers are hard to audit. Policy engines that evaluate code strings add injection risk, and naive attribute checks fail open when an attribute is missing or has an unexpected type.

## Decision

Use hierarchical RBAC plus ABAC rules with JSON condition trees, no code evaluation, and Kleene three-valued logic. Missing refs are indeterminate; an indeterminate deny rule denies, an indeterminate allow rule does not apply. Refs resolve with Object.hasOwn and forbidden segments are rejected at definition time. Comparisons are strict, with ordering limited to finite numbers. Policies are validated, copied and frozen once, with hard size and depth limits. Audit events carry no attribute values.

## Consequences

Authorization is reviewable and the role matrix is exportable to CSV and Markdown. Missing data always yields a denial, which can surprise authors who expect lenient behavior and must use exists to guard attributes. The condition language is deliberately small, with no functions or coercion, and policies that exceed the documented limits are rejected.
