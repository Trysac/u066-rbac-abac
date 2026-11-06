# Architecture

## Overview

`@trysac/rbac-abac` is a small, dependency-free TypeScript library published to npm as ES modules with type declarations. It evaluates hierarchical role grants and JSON attribute rules under deny-overrides, using fail-closed three-valued conditions, and exports role matrices.

## Modules

| Module | Responsibility |
|---|---|
| `src/index.ts` | Public API: `definePolicy`, `evaluate`, `exportMatrix`, `matrixToCsv`, `matrixToMarkdown`, `PolicyError`, and their types. Policy validation, condition parsing and evaluation, and matrix rendering all live in this file. |

The library currently has a single source module. Internal helpers are not exported.

## Boundaries

- No runtime dependencies. Any addition is justified in [STACK.md](STACK.md).
- No `node:` imports and no I/O. Conditions are data, never code: there is no `eval` or `Function`.
- Validated policies are stored in a module-level `WeakMap` keyed by the frozen policy object, so callers cannot forge internal state.
- All thrown errors are `PolicyError` instances with a stable `code`.

## Build and distribution

`npm run build` compiles `src/` to `dist/` with `tsconfig.build.json`. Only `dist/` is published (`files` in `package.json`).

## Decisions

Architectural decisions are recorded in [decisions/](decisions/), starting with [0001](decisions/0001-record-architecture-decisions.md).
