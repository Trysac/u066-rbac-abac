# Testing

## Tools

- [Vitest](https://vitest.dev/) runs the suite in `test/`.
- Coverage is collected with V8 (`@vitest/coverage-v8`) over `src/`.

## Test files

- `test/index.test.ts` is the only test file. It imports the public entry point `../src/index.js` and covers:
  - acceptance literals: the examples from the specification (role grants, cycles, deny-indeterminate, invalid requests);
  - roles and permissions: exact and wildcard grants, no wildcard leak across types, malformed permissions, unknown subject roles, freezing and input copying;
  - inheritance: chains, diamonds, cycle detection with role names, unknown parents, depth limit 16;
  - rules: deny overrides, allow rules, ownership conditions, no type coercion;
  - three-valued logic: a Kleene table over every operator, odd attribute values, prototype-chain reads, subject/resource/action/context refs, no code execution;
  - policy validation: refs, depth, node and list limits, malformed conditions, policies and rules, size limits, prototype pollution through role names;
  - evaluate input: malformed requests, subject role limit, foreign policy objects, `onDecision` validation;
  - `onDecision`: only decision data reaches the hook, observer errors are ignored, invalid requests do not notify;
  - matrix export and CSV and Markdown golden outputs, CSV injection guard and Markdown escaping.

## Commands

```sh
npm test            # vitest run --coverage
npx vitest          # watch mode while developing
npm run check       # every gate, including tests
```

## Rules

- Coverage must stay at or above 80 % for lines, branches, functions and statements (`vitest.config.ts`). Lowering the thresholds is not allowed.
- Test through the public entry point (`src/index.ts`) and assert observable behavior: return values, thrown errors and their codes.
- Each bug fix adds a test that fails without the fix.
- Tests are deterministic: no network, no real clock, no shared state between tests.

## Reports

Coverage reports are written to `coverage/` (text summary and `lcov`). The folder is ignored by git.
