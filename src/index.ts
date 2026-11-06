/**
 * Role and attribute based access control.
 *
 * Hierarchical RBAC (ANSI INCITS 359) combined with ABAC rules (NIST SP 800-162), resolved with the
 * XACML 3.0 deny-overrides algorithm. Conditions are JSON trees evaluated with three-valued (Kleene)
 * logic, so a missing attribute can never turn into an allow.
 *
 * @packageDocumentation
 */

/** Stable machine-readable error codes. */
export type PolicyErrorCode =
  | "invalid_policy"
  | "inheritance_cycle"
  | "limit_exceeded"
  | "invalid_request";

/** The single error type thrown by this library. */
export class PolicyError extends Error {
  /** Stable machine-readable error code. */
  readonly code: PolicyErrorCode;
  /** Problem descriptions, each at most 200 characters. */
  readonly problems: string[];

  constructor(code: PolicyErrorCode, message: string, problems?: string[]) {
    super(clip(message, 200));
    this.name = "PolicyError";
    this.code = code;
    this.problems = (problems ?? [message]).map((problem) => clip(problem, 200));
  }
}

/** A condition operand: a literal or a reference such as `{ ref: "resource.attributes.owner" }`. */
export type Operand = string | number | boolean | null | { readonly ref: string };

/** A JSON condition tree. */
export type Condition =
  | { readonly eq: readonly [Operand, Operand] }
  | { readonly ne: readonly [Operand, Operand] }
  | { readonly gt: readonly [Operand, Operand] }
  | { readonly gte: readonly [Operand, Operand] }
  | { readonly lt: readonly [Operand, Operand] }
  | { readonly lte: readonly [Operand, Operand] }
  | { readonly in: readonly [Operand, readonly Operand[]] }
  | { readonly and: readonly Condition[] }
  | { readonly or: readonly Condition[] }
  | { readonly not: Condition }
  | { readonly exists: Operand };

/** An attribute rule evaluated on top of the role grants. */
export interface Rule {
  readonly id: string;
  readonly effect: "allow" | "deny";
  readonly resource: string;
  /** An action name or `*`. */
  readonly action: string;
  readonly when?: Condition;
}

/** Role definition as supplied by the caller. */
export interface RoleInput {
  readonly permissions: readonly string[];
  readonly inherits?: readonly string[];
}

/** Input of {@link definePolicy}. */
export interface PolicyInput {
  readonly roles: Readonly<Record<string, RoleInput>>;
  readonly rules?: readonly Rule[];
}

/** A validated, frozen role definition. */
export interface RoleDefinition {
  readonly permissions: readonly string[];
  readonly inherits: readonly string[];
}

/** Public summary of a validated rule. */
export interface RuleSummary {
  readonly id: string;
  readonly effect: "allow" | "deny";
  readonly resource: string;
  readonly action: string;
  readonly hasCondition: boolean;
}

/** A validated policy created by {@link definePolicy}. */
export interface Policy {
  readonly roles: ReadonlyMap<string, RoleDefinition>;
  readonly rules: readonly RuleSummary[];
}

/** Free-form attribute bag. */
export type Attributes = Readonly<Record<string, unknown>>;

/** An authorization request. */
export interface AccessRequest {
  readonly subject: {
    readonly id: string;
    readonly roles: readonly string[];
    readonly attributes?: Attributes;
  };
  readonly action: string;
  readonly resource: {
    readonly type: string;
    readonly id?: string;
    readonly attributes?: Attributes;
  };
  readonly context?: Attributes;
}

/** Why a decision was taken. */
export type DecisionReason =
  | "deny-rule"
  | "deny-indeterminate"
  | "allow-rule"
  | "role"
  | "default-deny";

/** The result of {@link evaluate}. */
export interface Decision {
  readonly allowed: boolean;
  readonly reason: DecisionReason;
  readonly ruleId?: string;
}

/** Audit event passed to `onDecision`. It never carries attribute values. */
export interface DecisionEvent {
  readonly allowed: boolean;
  readonly reason: DecisionReason;
  readonly ruleId?: string;
  readonly action: string;
  readonly resourceType: string;
}

/** Options of {@link evaluate}. */
export interface EvaluateOptions {
  /** Called after each decision; exceptions it throws are ignored. */
  readonly onDecision?: (event: DecisionEvent) => void;
}

/** Role by permission matrix produced by {@link exportMatrix}. */
export interface PermissionMatrix {
  readonly roles: readonly string[];
  readonly permissions: readonly string[];
  readonly grants: Readonly<Record<string, readonly string[]>>;
}

const MAX_ROLES = 1000;
const MAX_RULES = 1000;
const MAX_INHERIT_DEPTH = 16;
const MAX_COND_DEPTH = 32;
const MAX_COND_NODES = 10_000;
const MAX_IN_LIST = 1000;
const MAX_STRING = 1024;
const MAX_NAME = 128;
const MAX_REF = 256;
const MAX_ROLE_PERMS = 1000;
const MAX_TOTAL_PERMS = 2000;
const MAX_SUBJECT_ROLES = 1000;

const ROLE_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const NAME_RE = /^[a-z][a-z0-9_-]*$/;
const PERMISSION_RE = /^[a-z][a-z0-9_-]*:(?:[a-z][a-z0-9_-]*|[*])$/;
const SEGMENT_RE = /^[A-Za-z0-9_]+$/;
const FORBIDDEN_SEGMENTS: ReadonlySet<string> = new Set(["__proto__", "prototype", "constructor"]);
const REF_ROOTS: ReadonlySet<string> = new Set(["subject", "resource", "action", "context"]);
const CMP_OPS = ["eq", "ne", "gt", "gte", "lt", "lte"] as const;
const MISSING = Symbol("missing");

type Roots = Record<string, unknown>;
type CmpOp = (typeof CMP_OPS)[number];
type Tri = boolean | null;

type Opnd =
  | { readonly kind: "lit"; readonly value: string | number | boolean | null }
  | { readonly kind: "ref"; readonly path: readonly string[] };

type Cond =
  | { readonly op: CmpOp; readonly left: Opnd; readonly right: Opnd }
  | { readonly op: "in"; readonly needle: Opnd; readonly list: readonly Opnd[] }
  | { readonly op: "and" | "or"; readonly items: readonly Cond[] }
  | { readonly op: "not"; readonly item: Cond }
  | { readonly op: "exists"; readonly operand: Opnd };

interface CompiledRule {
  readonly id: string;
  readonly effect: "allow" | "deny";
  readonly resource: string;
  readonly action: string;
  readonly cond: Cond | undefined;
}

interface Internals {
  readonly effective: ReadonlyMap<string, ReadonlySet<string>>;
  readonly rules: readonly CompiledRule[];
}

interface Counter {
  nodes: number;
}

interface Req {
  readonly roles: readonly string[];
  readonly action: string;
  readonly type: string;
  readonly roots: Roots;
}

const INTERNALS = new WeakMap<object, Internals>();

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 3)}...` : text;
}

function show(value: unknown): string {
  if (typeof value === "string") {
    return JSON.stringify(clip(value, 40));
  }
  if (value === null) {
    return "null";
  }
  return Array.isArray(value) ? "array" : typeof value;
}

function fail(code: PolicyErrorCode, problem: string): never {
  throw new PolicyError(code, problem, [problem]);
}

function bad(problem: string): never {
  return fail("invalid_request", problem);
}

function isObject(value: unknown): value is Roots {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPlain(value: unknown): value is Roots {
  if (!isObject(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function own(obj: Roots, key: string): unknown {
  return Object.hasOwn(obj, key) ? obj[key] : undefined;
}

function isName(value: unknown): value is string {
  return typeof value === "string" && value.length <= MAX_NAME && NAME_RE.test(value);
}

function isAction(value: unknown): value is string {
  return value === "*" || isName(value);
}

function isPermission(value: unknown): value is string {
  return typeof value === "string" && value.length <= MAX_STRING && PERMISSION_RE.test(value);
}

function isCmpOp(op: string): op is CmpOp {
  return (CMP_OPS as readonly string[]).includes(op);
}

function checkKeys(obj: Roots, allowed: readonly string[], what: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      fail("invalid_policy", `${what} has unknown key ${show(key)}`);
    }
  }
}

function countNode(counter: Counter): void {
  counter.nodes += 1;
  if (counter.nodes > MAX_COND_NODES) {
    fail("limit_exceeded", `conditions exceed ${MAX_COND_NODES} nodes`);
  }
}

function parseRef(path: unknown): readonly string[] {
  if (typeof path !== "string") {
    fail("invalid_policy", "ref must be a string");
  }
  if (path.length > MAX_REF) {
    fail("limit_exceeded", "ref path is too long");
  }
  const segments = path.split(".");
  if (!REF_ROOTS.has(segments[0] ?? "")) {
    fail(
      "invalid_policy",
      `ref ${show(path)} must start with subject, resource, action or context`,
    );
  }
  for (const segment of segments) {
    if (!SEGMENT_RE.test(segment) || FORBIDDEN_SEGMENTS.has(segment)) {
      fail("invalid_policy", `ref ${show(path)} has an invalid segment`);
    }
  }
  return Object.freeze(segments);
}

function parseOperand(raw: unknown, counter: Counter): Opnd {
  countNode(counter);
  if (raw === null || typeof raw === "boolean") {
    return { kind: "lit", value: raw };
  }
  if (typeof raw === "number") {
    if (!Number.isFinite(raw)) {
      fail("invalid_policy", "numeric operands must be finite");
    }
    return { kind: "lit", value: raw };
  }
  if (typeof raw === "string") {
    if (raw.length > MAX_STRING) {
      fail("limit_exceeded", "string operand is too long");
    }
    return { kind: "lit", value: raw };
  }
  if (isPlain(raw)) {
    const keys = Object.keys(raw);
    if (keys.length === 1 && keys[0] === "ref") {
      return { kind: "ref", path: parseRef(raw.ref) };
    }
  }
  return fail("invalid_policy", `invalid operand ${show(raw)}`);
}

function parsePair(arg: unknown, counter: Counter): [Opnd, Opnd] {
  if (!Array.isArray(arg) || arg.length !== 2) {
    fail("invalid_policy", "comparison needs exactly two operands");
  }
  return [parseOperand(arg[0], counter), parseOperand(arg[1], counter)];
}

function parseIn(arg: unknown, counter: Counter): Cond {
  if (!Array.isArray(arg) || arg.length !== 2 || !Array.isArray(arg[1])) {
    fail("invalid_policy", "in needs [operand, [operands]]");
  }
  const rawList: unknown[] = arg[1];
  if (rawList.length > MAX_IN_LIST) {
    fail("limit_exceeded", `in lists are limited to ${MAX_IN_LIST} items`);
  }
  const needle = parseOperand(arg[0], counter);
  const list: Opnd[] = [];
  for (const item of rawList) {
    list.push(parseOperand(item, counter));
  }
  return { op: "in", needle, list };
}

function parseItems(arg: unknown, depth: number, counter: Counter): Cond[] {
  if (!Array.isArray(arg) || arg.length === 0) {
    fail("invalid_policy", "and/or need a non-empty array");
  }
  const items: Cond[] = [];
  for (const item of arg) {
    items.push(parseCond(item, depth + 1, counter));
  }
  return items;
}

function parseCond(raw: unknown, depth: number, counter: Counter): Cond {
  if (depth > MAX_COND_DEPTH) {
    fail("limit_exceeded", `condition depth exceeds ${MAX_COND_DEPTH}`);
  }
  countNode(counter);
  if (!isPlain(raw)) {
    fail("invalid_policy", `condition must be an object, got ${show(raw)}`);
  }
  const keys = Object.keys(raw);
  const op = keys[0];
  if (keys.length !== 1 || op === undefined) {
    fail("invalid_policy", "condition needs exactly one operator");
  }
  const arg = raw[op];
  if (isCmpOp(op)) {
    const [left, right] = parsePair(arg, counter);
    return { op, left, right };
  }
  switch (op) {
    case "in":
      return parseIn(arg, counter);
    case "and":
    case "or":
      return { op, items: parseItems(arg, depth, counter) };
    case "not":
      return { op, item: parseCond(arg, depth + 1, counter) };
    case "exists":
      return { op, operand: parseOperand(arg, counter) };
    default:
      return fail("invalid_policy", `unknown operator ${show(op)}`);
  }
}

function parseInherits(raw: unknown): string[] {
  if (raw === undefined) {
    return [];
  }
  if (!Array.isArray(raw)) {
    fail("invalid_policy", "inherits must be an array");
  }
  if (raw.length > MAX_ROLES) {
    fail("limit_exceeded", "inherits list is too large");
  }
  const parents = new Set<string>();
  for (const parent of raw) {
    if (typeof parent !== "string") {
      fail("invalid_policy", "inherits must hold role names");
    }
    parents.add(parent);
  }
  return [...parents];
}

function parseRole(name: string, raw: unknown): RoleDefinition {
  if (!ROLE_RE.test(name)) {
    fail("invalid_policy", `invalid role name ${show(name)}`);
  }
  if (!isPlain(raw)) {
    fail("invalid_policy", `role ${show(name)} must be an object`);
  }
  checkKeys(raw, ["permissions", "inherits"], "role");
  const perms = own(raw, "permissions");
  if (!Array.isArray(perms)) {
    fail("invalid_policy", `role ${show(name)} needs a permissions array`);
  }
  if (perms.length > MAX_ROLE_PERMS) {
    fail("limit_exceeded", `role ${show(name)} has too many permissions`);
  }
  const granted = new Set<string>();
  for (const perm of perms) {
    if (!isPermission(perm)) {
      fail("invalid_policy", `invalid permission ${show(perm)}`);
    }
    granted.add(perm);
  }
  const parents = parseInherits(own(raw, "inherits"));
  return Object.freeze({
    permissions: Object.freeze([...granted].sort()),
    inherits: Object.freeze(parents),
  });
}

function checkParents(roles: ReadonlyMap<string, RoleDefinition>): void {
  for (const [name, def] of roles) {
    for (const parent of def.inherits) {
      if (!roles.has(parent)) {
        fail("invalid_policy", `role ${show(name)} inherits unknown role ${show(parent)}`);
      }
    }
  }
}

function checkInheritance(roles: ReadonlyMap<string, RoleDefinition>): void {
  const depths = new Map<string, number>();
  const active: string[] = [];
  const visit = (name: string): number => {
    const known = depths.get(name);
    if (known !== undefined) {
      return known;
    }
    active.push(name);
    let depth = 0;
    for (const parent of roles.get(name)?.inherits ?? []) {
      const at = active.indexOf(parent);
      if (at >= 0) {
        const cycle = [...active.slice(at), parent].join(" -> ");
        fail("inheritance_cycle", `inheritance cycle: ${cycle}`);
      }
      depth = Math.max(depth, visit(parent) + 1);
    }
    if (depth > MAX_INHERIT_DEPTH) {
      fail("limit_exceeded", `inheritance deeper than ${MAX_INHERIT_DEPTH}`);
    }
    active.pop();
    depths.set(name, depth);
    return depth;
  };
  for (const name of roles.keys()) {
    visit(name);
  }
}

function checkTotalPermissions(roles: ReadonlyMap<string, RoleDefinition>): void {
  const all = new Set<string>();
  for (const def of roles.values()) {
    for (const perm of def.permissions) {
      all.add(perm);
    }
  }
  if (all.size > MAX_TOTAL_PERMS) {
    fail("limit_exceeded", `a policy may declare at most ${MAX_TOTAL_PERMS} permissions`);
  }
}

function effectivePermissions(
  roles: ReadonlyMap<string, RoleDefinition>,
): Map<string, ReadonlySet<string>> {
  const out = new Map<string, ReadonlySet<string>>();
  const resolveRole = (name: string): ReadonlySet<string> => {
    const known = out.get(name);
    if (known !== undefined) {
      return known;
    }
    const set = new Set<string>();
    const def = roles.get(name);
    for (const perm of def?.permissions ?? []) {
      set.add(perm);
    }
    for (const parent of def?.inherits ?? []) {
      for (const perm of resolveRole(parent)) {
        set.add(perm);
      }
    }
    out.set(name, set);
    return set;
  };
  for (const name of roles.keys()) {
    resolveRole(name);
  }
  return out;
}

function parseRule(raw: unknown, counter: Counter): CompiledRule {
  if (!isPlain(raw)) {
    fail("invalid_policy", `rule must be an object, got ${show(raw)}`);
  }
  checkKeys(raw, ["id", "effect", "resource", "action", "when"], "rule");
  const id = own(raw, "id");
  if (typeof id !== "string" || id.length < 1 || id.length > MAX_NAME) {
    fail("invalid_policy", `rule id must be a string of 1 to ${MAX_NAME} characters`);
  }
  const effect = own(raw, "effect");
  if (effect !== "allow" && effect !== "deny") {
    fail("invalid_policy", `rule ${show(id)} needs effect allow or deny`);
  }
  const resource = own(raw, "resource");
  if (!isName(resource)) {
    fail("invalid_policy", `rule ${show(id)} has an invalid resource`);
  }
  const action = own(raw, "action");
  if (!isAction(action)) {
    fail("invalid_policy", `rule ${show(id)} has an invalid action`);
  }
  const when = own(raw, "when");
  const cond = when === undefined ? undefined : parseCond(when, 1, counter);
  return { id, effect, resource, action, cond };
}

function parseRules(raw: unknown): CompiledRule[] {
  if (raw === undefined) {
    return [];
  }
  if (!Array.isArray(raw)) {
    fail("invalid_policy", "rules must be an array");
  }
  if (raw.length > MAX_RULES) {
    fail("limit_exceeded", `a policy may hold at most ${MAX_RULES} rules`);
  }
  const counter: Counter = { nodes: 0 };
  const ids = new Set<string>();
  const rules: CompiledRule[] = [];
  for (const item of raw) {
    const rule = parseRule(item, counter);
    if (ids.has(rule.id)) {
      fail("invalid_policy", `duplicate rule id ${show(rule.id)}`);
    }
    ids.add(rule.id);
    rules.push(rule);
  }
  return rules;
}

function summarize(rule: CompiledRule): RuleSummary {
  const { id, effect, resource, action } = rule;
  return Object.freeze({ id, effect, resource, action, hasCondition: rule.cond !== undefined });
}

/**
 * Validates a policy and returns a frozen {@link Policy}.
 *
 * Role names, permissions (`resource:action` or `resource:*`), references, nesting depth, node counts
 * and list sizes are all checked; the input object is copied, so later mutation has no effect.
 *
 * @param input - Roles with optional inheritance plus optional attribute rules.
 * @returns The validated policy.
 * @throws {PolicyError} `invalid_policy`, `inheritance_cycle` or `limit_exceeded`.
 */
export function definePolicy(input: PolicyInput): Policy {
  const raw: unknown = input;
  if (!isPlain(raw)) {
    fail("invalid_policy", "policy must be an object");
  }
  checkKeys(raw, ["roles", "rules"], "policy");
  const rolesRaw = own(raw, "roles");
  if (!isPlain(rolesRaw)) {
    fail("invalid_policy", "roles must be an object");
  }
  const names = Object.keys(rolesRaw);
  if (names.length > MAX_ROLES) {
    fail("limit_exceeded", `a policy may hold at most ${MAX_ROLES} roles`);
  }
  const roles = new Map<string, RoleDefinition>();
  for (const name of names) {
    roles.set(name, parseRole(name, rolesRaw[name]));
  }
  checkParents(roles);
  checkInheritance(roles);
  checkTotalPermissions(roles);
  const effective = effectivePermissions(roles);
  const rules = parseRules(own(raw, "rules"));
  const summaries = Object.freeze(rules.map(summarize));
  const policy: Policy = Object.freeze({ roles, rules: summaries });
  INTERNALS.set(policy, { effective, rules });
  return policy;
}

function resolveOperand(operand: Opnd, roots: Roots): unknown {
  if (operand.kind === "lit") {
    return operand.value;
  }
  let current: unknown = roots;
  for (const segment of operand.path) {
    if (typeof current !== "object" || current === null) {
      return MISSING;
    }
    if (!Object.hasOwn(current, segment)) {
      return MISSING;
    }
    current = (current as Roots)[segment];
  }
  return current === undefined ? MISSING : current;
}

function compare(op: CmpOp, left: unknown, right: unknown): Tri {
  if (left === MISSING || right === MISSING) {
    return null;
  }
  if (op === "eq") {
    return left === right;
  }
  if (op === "ne") {
    return left !== right;
  }
  if (typeof left !== "number" || typeof right !== "number") {
    return false;
  }
  if (!Number.isFinite(left) || !Number.isFinite(right)) {
    return false;
  }
  switch (op) {
    case "gt":
      return left > right;
    case "gte":
      return left >= right;
    case "lt":
      return left < right;
    default:
      return left <= right;
  }
}

function evalCond(cond: Cond, roots: Roots): Tri {
  switch (cond.op) {
    case "eq":
    case "ne":
    case "gt":
    case "gte":
    case "lt":
    case "lte": {
      const left = resolveOperand(cond.left, roots);
      const right = resolveOperand(cond.right, roots);
      return compare(cond.op, left, right);
    }
    case "in": {
      const needle = resolveOperand(cond.needle, roots);
      if (needle === MISSING) {
        return null;
      }
      let sawMissing = false;
      for (const item of cond.list) {
        const value = resolveOperand(item, roots);
        if (value === MISSING) {
          sawMissing = true;
        } else if (value === needle) {
          return true;
        }
      }
      return sawMissing ? null : false;
    }
    case "and": {
      let sawNull = false;
      for (const item of cond.items) {
        const value = evalCond(item, roots);
        if (value === false) {
          return false;
        }
        if (value === null) {
          sawNull = true;
        }
      }
      return sawNull ? null : true;
    }
    case "or": {
      let sawNull = false;
      for (const item of cond.items) {
        const value = evalCond(item, roots);
        if (value === true) {
          return true;
        }
        if (value === null) {
          sawNull = true;
        }
      }
      return sawNull ? null : false;
    }
    case "not": {
      const value = evalCond(cond.item, roots);
      return value === null ? null : !value;
    }
    case "exists":
      return resolveOperand(cond.operand, roots) !== MISSING;
  }
}

function checkOptionalObject(obj: Roots, key: string, label: string): void {
  const value = own(obj, key);
  if (value !== undefined && !isObject(value)) {
    bad(`${label} must be an object`);
  }
}

function parseRequest(raw: unknown): Req {
  if (!isObject(raw)) {
    bad("request must be an object");
  }
  const subject = own(raw, "subject");
  if (!isObject(subject)) {
    bad("subject must be an object");
  }
  const id = own(subject, "id");
  if (typeof id !== "string" || id.length > MAX_STRING) {
    bad("subject.id must be a string");
  }
  const rawRoles = own(subject, "roles");
  if (!Array.isArray(rawRoles)) {
    bad("subject.roles must be an array");
  }
  if (rawRoles.length > MAX_SUBJECT_ROLES) {
    fail("limit_exceeded", `subject.roles is limited to ${MAX_SUBJECT_ROLES} entries`);
  }
  const roles: string[] = [];
  for (const role of rawRoles) {
    if (typeof role !== "string") {
      bad("subject.roles must hold strings");
    }
    roles.push(role);
  }
  checkOptionalObject(subject, "attributes", "subject.attributes");
  const action = own(raw, "action");
  if (!isName(action)) {
    bad(`action must match ${NAME_RE.source}, got ${show(action)}`);
  }
  const resource = own(raw, "resource");
  if (!isObject(resource)) {
    bad("resource must be an object");
  }
  const type = own(resource, "type");
  if (!isName(type)) {
    bad(`resource.type must match ${NAME_RE.source}, got ${show(type)}`);
  }
  const resourceId = own(resource, "id");
  if (resourceId !== undefined && typeof resourceId !== "string") {
    bad("resource.id must be a string");
  }
  checkOptionalObject(resource, "attributes", "resource.attributes");
  checkOptionalObject(raw, "context", "context");
  const roots: Roots = { subject, resource, action, context: own(raw, "context") };
  return { roles, action, type, roots };
}

function decision(allowed: boolean, reason: DecisionReason, ruleId?: string): Decision {
  if (ruleId === undefined) {
    return Object.freeze({ allowed, reason });
  }
  return Object.freeze({ allowed, reason, ruleId });
}

function matches(rule: CompiledRule, req: Req): boolean {
  return rule.resource === req.type && (rule.action === "*" || rule.action === req.action);
}

function ruleResult(rule: CompiledRule, roots: Roots): Tri {
  return rule.cond === undefined ? true : evalCond(rule.cond, roots);
}

function decide(internals: Internals, req: Req): Decision {
  let pending: string | undefined;
  for (const rule of internals.rules) {
    if (rule.effect !== "deny" || !matches(rule, req)) {
      continue;
    }
    const result = ruleResult(rule, req.roots);
    if (result === true) {
      return decision(false, "deny-rule", rule.id);
    }
    if (result === null && pending === undefined) {
      pending = rule.id;
    }
  }
  if (pending !== undefined) {
    return decision(false, "deny-indeterminate", pending);
  }
  for (const rule of internals.rules) {
    if (rule.effect === "allow" && matches(rule, req) && ruleResult(rule, req.roots) === true) {
      return decision(true, "allow-rule", rule.id);
    }
  }
  const exact = `${req.type}:${req.action}`;
  const wildcard = `${req.type}:*`;
  for (const role of req.roles) {
    const perms = internals.effective.get(role);
    if (perms !== undefined && (perms.has(exact) || perms.has(wildcard))) {
      return decision(true, "role");
    }
  }
  return decision(false, "default-deny");
}

function notify(handler: (event: DecisionEvent) => void, result: Decision, req: Req): void {
  const base = {
    allowed: result.allowed,
    reason: result.reason,
    action: req.action,
    resourceType: req.type,
  };
  const event: DecisionEvent =
    result.ruleId === undefined ? base : { ...base, ruleId: result.ruleId };
  try {
    handler(Object.freeze(event));
  } catch {
    // Observer failures must never change an authorization decision.
  }
}

/**
 * Evaluates an access request against a policy.
 *
 * Order: deny rules (true gives `deny-rule`, indeterminate gives `deny-indeterminate`), then allow
 * rules (only true applies), then role grants including inherited ones, then `default-deny`.
 * Unknown subject roles are ignored. Missing attributes never produce an allow.
 *
 * @param policy - A policy created by {@link definePolicy}.
 * @param req - The request; `action` and `resource.type` must match `^[a-z][a-z0-9_-]*$`.
 * @param options - Optional `onDecision` audit hook that never sees attribute values.
 * @returns The decision.
 * @throws {PolicyError} `invalid_request` for malformed requests, `limit_exceeded` for oversized ones.
 */
export function evaluate(policy: Policy, req: AccessRequest, options?: EvaluateOptions): Decision {
  const internals = INTERNALS.get(policy);
  if (internals === undefined) {
    bad("policy was not created by definePolicy");
  }
  const handler = options?.onDecision;
  if (handler !== undefined && typeof handler !== "function") {
    bad("onDecision must be a function");
  }
  const parsed = parseRequest(req);
  const result = decide(internals, parsed);
  if (handler !== undefined) {
    notify(handler, result, parsed);
  }
  return result;
}

/**
 * Exports the role by permission matrix with grants resolved through inheritance.
 *
 * @param policy - A policy created by {@link definePolicy}.
 * @returns Roles, permissions and per-role grants, all sorted.
 * @throws {PolicyError} `invalid_policy` when `policy` was not created by {@link definePolicy}.
 */
export function exportMatrix(policy: Policy): PermissionMatrix {
  const internals = INTERNALS.get(policy);
  if (internals === undefined) {
    fail("invalid_policy", "policy was not created by definePolicy");
  }
  const roles = [...internals.effective.keys()].sort();
  const all = new Set<string>();
  const grants: Record<string, string[]> = {};
  for (const role of roles) {
    const list = [...(internals.effective.get(role) ?? [])].sort();
    grants[role] = list;
    for (const perm of list) {
      all.add(perm);
    }
  }
  return { roles, permissions: [...all].sort(), grants };
}

interface ReadMatrix {
  readonly roles: string[];
  readonly permissions: string[];
  readonly grants: ReadonlyMap<string, ReadonlySet<string>>;
}

function readStrings(value: unknown, max: number, label: string): string[] {
  if (!Array.isArray(value)) {
    fail("invalid_policy", `matrix ${label} must be an array`);
  }
  if (value.length > max) {
    fail("limit_exceeded", `matrix ${label} is limited to ${max} entries`);
  }
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") {
      fail("invalid_policy", `matrix ${label} must hold strings`);
    }
    if (item.length > MAX_STRING) {
      fail("limit_exceeded", `matrix ${label} holds a string that is too long`);
    }
    out.push(item);
  }
  return out;
}

function readMatrix(raw: unknown): ReadMatrix {
  if (!isObject(raw)) {
    fail("invalid_policy", "matrix must be an object");
  }
  const roles = readStrings(own(raw, "roles"), MAX_ROLES, "roles");
  const permissions = readStrings(own(raw, "permissions"), MAX_TOTAL_PERMS, "permissions");
  const grantsRaw = own(raw, "grants");
  if (!isObject(grantsRaw)) {
    fail("invalid_policy", "matrix grants must be an object");
  }
  const grants = new Map<string, ReadonlySet<string>>();
  for (const role of roles) {
    const list = own(grantsRaw, role);
    const items = list === undefined ? [] : readStrings(list, MAX_TOTAL_PERMS, "grants");
    grants.set(role, new Set(items));
  }
  return { roles, permissions, grants };
}

function mark(granted: ReadonlySet<string> | undefined, permission: string): string {
  if (granted?.has(permission)) {
    return "x";
  }
  return "";
}

function csvCell(value: string): string {
  const guarded = /^[=+@\t\r-]/.test(value) ? `'${value}` : value;
  if (/[",\r\n]/.test(guarded)) {
    return `"${guarded.replaceAll('"', '""')}"`;
  }
  return guarded;
}

function csvRow(cells: readonly string[]): string {
  return cells.map(csvCell).join(",");
}

function mdCell(value: string): string {
  return value
    .replaceAll("\\", "\\\\")
    .replaceAll("|", "\\|")
    .replace(/[\r\n]+/g, " ");
}

function mdRow(cells: readonly string[]): string {
  return `| ${cells.join(" | ")} |`;
}

/**
 * Renders a matrix as RFC 4180 CSV (CRLF rows, doubled quotes) with the OWASP CSV Injection guard:
 * cells starting with `=`, `+`, `-`, `@`, tab or CR get a leading apostrophe.
 *
 * @param matrix - A matrix from {@link exportMatrix} or a hand-built one.
 * @returns CSV text; a granted cell is `x`, any other cell is empty.
 * @throws {PolicyError} `invalid_policy` for a malformed matrix, `limit_exceeded` for an oversized one.
 */
export function matrixToCsv(matrix: PermissionMatrix): string {
  const parsed = readMatrix(matrix);
  const lines = [csvRow(["role", ...parsed.permissions])];
  for (const role of parsed.roles) {
    const granted = parsed.grants.get(role);
    const cells = parsed.permissions.map((permission) => mark(granted, permission));
    lines.push(csvRow([role, ...cells]));
  }
  return `${lines.join("\r\n")}\r\n`;
}

/**
 * Renders a matrix as a Markdown table. Pipes and backslashes are escaped and line breaks become spaces.
 *
 * @param matrix - A matrix from {@link exportMatrix} or a hand-built one.
 * @returns Markdown text ending with a newline.
 * @throws {PolicyError} `invalid_policy` for a malformed matrix, `limit_exceeded` for an oversized one.
 */
export function matrixToMarkdown(matrix: PermissionMatrix): string {
  const parsed = readMatrix(matrix);
  const head = ["role", ...parsed.permissions].map(mdCell);
  const lines = [mdRow(head), mdRow(head.map(() => "---"))];
  for (const role of parsed.roles) {
    const granted = parsed.grants.get(role);
    const cells = parsed.permissions.map((permission) => mark(granted, permission));
    lines.push(mdRow([mdCell(role), ...cells]));
  }
  return `${lines.join("\n")}\n`;
}
