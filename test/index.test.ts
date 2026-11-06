import { describe, expect, it } from "vitest";
import * as rbac from "../src/index.js";

const { PolicyError, definePolicy, evaluate, exportMatrix } = rbac;
const { matrixToCsv, matrixToMarkdown } = rbac;

type Req = rbac.AccessRequest;
type Attrs = Record<string, unknown>;

function raises(fn: () => unknown): rbac.PolicyError {
  try {
    fn();
  } catch (error) {
    if (error instanceof PolicyError) {
      return error;
    }
    throw error;
  }
  throw new Error("expected a PolicyError");
}

function pol(input: unknown): rbac.Policy {
  return definePolicy(input as rbac.PolicyInput);
}

function req(roles: string[], action: string, attrs: Attrs = {}): Req {
  return { subject: { id: "u1", roles }, action, resource: { type: "doc", attributes: attrs } };
}

const VIEWER = { viewer: { permissions: ["doc:read"] } };
const M = { ref: "resource.attributes.missing" };
const ok = { allowed: true, reason: "role" };
const denied = { allowed: false, reason: "default-deny" };

function denyWhen(when: unknown): rbac.Policy {
  const rule = { id: "r1", effect: "deny", resource: "doc", action: "read", when };
  return pol({ roles: VIEWER, rules: [rule] });
}

function outcome(when: unknown, attrs: Attrs = {}): string {
  return evaluate(denyWhen(when), req(["viewer"], "read", attrs)).reason;
}

function allowWhen(when: unknown): rbac.Policy {
  const rule = { id: "a1", effect: "allow", resource: "doc", action: "read", when };
  return pol({ roles: {}, rules: [rule] });
}

function nest(levels: number): unknown {
  let cond: unknown = { eq: [1, 1] };
  for (let i = 0; i < levels; i += 1) {
    cond = { not: cond };
  }
  return cond;
}

describe("acceptance literals", () => {
  it("roles 'a' and 'b' inheriting each other throw PolicyError code 'inheritance_cycle' whose problems name 'a' and 'b'", () => {
    const e = raises(() =>
      pol({
        roles: { a: { permissions: [], inherits: ["b"] }, b: { permissions: [], inherits: ["a"] } },
      }),
    );
    expect(e.code).toBe("inheritance_cycle");
    expect(e.problems.join(" ")).toContain("a");
    expect(e.problems.join(" ")).toContain("b");
  });

  it("deny rules with id 'r1' both return {allowed: false, reason: 'deny-indeterminate', ruleId: 'r1'}, while an allow rule with a missing ref does not apply and the result is 'default-deny'", () => {
    const expected = { allowed: false, reason: "deny-indeterminate", ruleId: "r1" };
    const eqM = { eq: [M, 1] };
    expect(evaluate(denyWhen(eqM), req(["viewer"], "read"))).toEqual(expected);
    expect(evaluate(denyWhen({ not: eqM }), req(["viewer"], "read"))).toEqual(expected);
    expect(evaluate(allowWhen(eqM), req([], "read"))).toEqual(denied);
  });

  it("{eq: ['1', 1]} is false; {gt: ['2', 1]} is false", () => {
    expect(outcome({ eq: ["1", 1] })).toBe("role");
    expect(outcome({ gt: ["2", 1] })).toBe("role");
  });

  it("evaluate with action '*' or resource type 'Doc!' throws PolicyError code 'invalid_request'", () => {
    const p = pol({ roles: VIEWER });
    expect(raises(() => evaluate(p, req(["viewer"], "*"))).code).toBe("invalid_request");
    const bad = { ...req(["viewer"], "read"), resource: { type: "Doc!" } };
    expect(raises(() => evaluate(p, bad)).code).toBe("invalid_request");
  });
});

function chain(edges: number): unknown {
  const roles: Record<string, { permissions: string[]; inherits?: string[] }> = {};
  for (let i = 0; i <= edges; i += 1) {
    if (i < edges) {
      roles[`r${i}`] = { permissions: [], inherits: [`r${i + 1}`] };
    } else {
      roles[`r${i}`] = { permissions: ["doc:read"] };
    }
  }
  return { roles };
}

function perms(start: number, count: number): string[] {
  return Array.from({ length: count }, (_, i) => `p${start + i}:read`);
}

describe("roles and permissions", () => {
  const policy = pol({
    roles: { reader: { permissions: ["doc:read"] }, owner: { permissions: ["doc:*"] } },
  });

  it("allows exact and wildcard permissions and denies by default", () => {
    expect(evaluate(policy, req(["reader"], "read"))).toEqual(ok);
    expect(evaluate(policy, req(["owner"], "delete"))).toEqual(ok);
    expect(evaluate(policy, req(["reader"], "write"))).toEqual(denied);
  });

  it("does not leak a wildcard across resource types", () => {
    const other: Req = { ...req(["owner"], "read"), resource: { type: "file" } };
    expect(evaluate(policy, other)).toEqual(denied);
  });

  it("rejects malformed permissions", () => {
    const list = ["doc:read:x", "doc:", " doc:read", "Doc:read", "doc:*:x", "*:read"];
    list.push("doc:read ", "doc:re ad", "", "doc:\nread", "doc:read\n", ":read", "doc");
    for (const permission of list) {
      const input = { roles: { a: { permissions: [permission] } } };
      expect(raises(() => pol(input)).code, permission).toBe("invalid_policy");
    }
    const nonString = { roles: { a: { permissions: [5] } } };
    expect(raises(() => pol(nonString)).code).toBe("invalid_policy");
  });

  it("ignores unknown subject roles", () => {
    expect(evaluate(policy, req(["ghost", "__proto__", "constructor"], "read"))).toEqual(denied);
  });

  it("freezes the policy and copies its input", () => {
    const list = ["doc:read"];
    const copy = pol({ roles: { viewer: { permissions: list } } });
    list.push("doc:write");
    expect(evaluate(copy, req(["viewer"], "write"))).toEqual(denied);
    expect(Object.isFrozen(copy)).toBe(true);
    expect(Object.isFrozen(copy.roles.get("viewer"))).toBe(true);
    expect(copy.roles.get("viewer")?.permissions).toEqual(["doc:read"]);
  });

  it("freezes decisions", () => {
    expect(Object.isFrozen(evaluate(policy, req(["reader"], "read")))).toBe(true);
  });
});

describe("inheritance", () => {
  it("gives admin the permissions of editor", () => {
    const policy = pol({
      roles: {
        editor: { permissions: ["doc:read"] },
        admin: { permissions: ["doc:delete"], inherits: ["editor"] },
      },
    });
    expect(evaluate(policy, req(["admin"], "read"))).toEqual(ok);
    expect(evaluate(policy, req(["admin"], "delete"))).toEqual(ok);
    expect(evaluate(policy, req(["editor"], "delete"))).toEqual(denied);
  });

  it("supports diamonds", () => {
    const policy = pol({
      roles: {
        base: { permissions: ["doc:read"] },
        left: { permissions: [], inherits: ["base"] },
        right: { permissions: [], inherits: ["base", "base"] },
        top: { permissions: [], inherits: ["left", "right"] },
      },
    });
    expect(evaluate(policy, req(["top"], "read"))).toEqual(ok);
  });

  it("detects cycles and names the roles", () => {
    const roles = {
      a: { permissions: [], inherits: ["b"] },
      b: { permissions: [], inherits: ["a"] },
    };
    const error = raises(() => pol({ roles }));
    expect(error.code).toBe("inheritance_cycle");
    expect(error.problems.join(" ")).toContain("a -> b -> a");
    const self = { roles: { a: { permissions: [], inherits: ["a"] } } };
    expect(raises(() => pol(self)).code).toBe("inheritance_cycle");
  });

  it("rejects unknown parents and bad inherits", () => {
    const unknown = { roles: { a: { permissions: [], inherits: ["nope"] } } };
    expect(raises(() => pol(unknown)).code).toBe("invalid_policy");
    const notArray = { roles: { a: { permissions: [], inherits: "b" } } };
    expect(raises(() => pol(notArray)).code).toBe("invalid_policy");
    const notString = { roles: { a: { permissions: [], inherits: [1] } } };
    expect(raises(() => pol(notString)).code).toBe("invalid_policy");
    const huge = { roles: { a: { permissions: [], inherits: Array(1001).fill("a") } } };
    expect(raises(() => pol(huge)).code).toBe("limit_exceeded");
  });

  it("limits inheritance depth to 16", () => {
    expect(evaluate(pol(chain(16)), req(["r0"], "read"))).toEqual(ok);
    expect(raises(() => pol(chain(17))).code).toBe("limit_exceeded");
  });
});

describe("rules", () => {
  const archived = {
    id: "no-archived",
    effect: "deny",
    resource: "doc",
    action: "write",
    when: { eq: [{ ref: "resource.attributes.status" }, "archived"] },
  };
  const policy = pol({ roles: { editor: { permissions: ["doc:write"] } }, rules: [archived] });

  it("lets a matching deny rule override a role grant", () => {
    const result = evaluate(policy, req(["editor"], "write", { status: "archived" }));
    expect(result).toEqual({ allowed: false, reason: "deny-rule", ruleId: "no-archived" });
    expect(evaluate(policy, req(["editor"], "write", { status: "draft" }))).toEqual(ok);
  });

  it("fails closed when a deny condition is indeterminate", () => {
    const conditions = [{ eq: [M, 1] }, { not: { eq: [M, 1] } }];
    for (const when of conditions) {
      const result = evaluate(denyWhen(when), req(["viewer"], "read"));
      expect(result).toEqual({ allowed: false, reason: "deny-indeterminate", ruleId: "r1" });
    }
  });

  it("does not apply an allow rule with a missing ref", () => {
    const result = evaluate(allowWhen({ eq: [M, 1] }), req([], "read"));
    expect(result).toEqual({ allowed: false, reason: "default-deny" });
  });

  it("allows through an allow rule and lets deny override it", () => {
    const allowed = evaluate(allowWhen({ eq: [1, 1] }), req([], "read"));
    expect(allowed).toEqual({ allowed: true, reason: "allow-rule", ruleId: "a1" });
    const allow = { id: "a1", effect: "allow", resource: "doc", action: "*" };
    const deny = { id: "d1", effect: "deny", resource: "doc", action: "read" };
    const both = pol({ roles: {}, rules: [allow, deny] });
    const result = evaluate(both, req([], "read"));
    expect(result).toEqual({ allowed: false, reason: "deny-rule", ruleId: "d1" });
    expect(evaluate(both, req([], "write"))).toEqual({
      allowed: true,
      reason: "allow-rule",
      ruleId: "a1",
    });
  });

  it("prefers a definite deny over an earlier indeterminate one", () => {
    const first = {
      id: "first",
      effect: "deny",
      resource: "doc",
      action: "read",
      when: { eq: [M, 1] },
    };
    const second = { id: "second", effect: "deny", resource: "doc", action: "*" };
    const both = pol({ roles: VIEWER, rules: [first, second] });
    expect(evaluate(both, req(["viewer"], "read")).ruleId).toBe("second");
  });

  it("ignores rules of other resources and actions", () => {
    const other = { id: "x", effect: "deny", resource: "file", action: "read" };
    const write = { id: "y", effect: "deny", resource: "doc", action: "write" };
    const both = pol({ roles: VIEWER, rules: [other, write] });
    expect(evaluate(both, req(["viewer"], "read"))).toEqual(ok);
  });

  it("allows the owner and denies others", () => {
    const owner = { eq: [{ ref: "subject.id" }, { ref: "resource.attributes.ownerId" }] };
    const rule = { id: "own", effect: "allow", resource: "doc", action: "edit", when: owner };
    const policy2 = pol({ roles: {}, rules: [rule] });
    const mine = evaluate(policy2, req([], "edit", { ownerId: "u1" }));
    expect(mine).toEqual({ allowed: true, reason: "allow-rule", ruleId: "own" });
    expect(evaluate(policy2, req([], "edit", { ownerId: "u2" }))).toEqual(denied);
    expect(evaluate(policy2, req([], "edit"))).toEqual(denied);
  });

  it("does not coerce types", () => {
    expect(evaluate(allowWhen({ eq: ["1", 1] }), req([], "read"))).toEqual(denied);
    expect(evaluate(allowWhen({ gt: ["2", 1] }), req([], "read"))).toEqual(denied);
    const fromAttr = allowWhen({ gt: [{ ref: "resource.attributes.n" }, 1] });
    expect(evaluate(fromAttr, req([], "read", { n: "2" }))).toEqual(denied);
  });
});

describe("three-valued logic", () => {
  const table: Array<[string, unknown, string]> = [
    ["and-false", { and: [{ eq: [1, 2] }, { eq: [M, 1] }] }, "role"],
    ["and-null", { and: [{ eq: [1, 1] }, { eq: [M, 1] }] }, "deny-indeterminate"],
    ["and-true", { and: [{ eq: [1, 1] }, { eq: [2, 2] }] }, "deny-rule"],
    ["or-true", { or: [{ eq: [1, 1] }, { eq: [M, 1] }] }, "deny-rule"],
    ["or-null", { or: [{ eq: [1, 2] }, { eq: [M, 1] }] }, "deny-indeterminate"],
    ["or-false", { or: [{ eq: [1, 2] }, { eq: [2, 3] }] }, "role"],
    ["not-false", { not: { eq: [1, 1] } }, "role"],
    ["not-true", { not: { eq: [1, 2] } }, "deny-rule"],
    ["exists-missing", { exists: M }, "role"],
    ["not-exists", { not: { exists: M } }, "deny-rule"],
    ["exists-literal", { exists: 0 }, "deny-rule"],
    ["ne-missing", { ne: [M, 1] }, "deny-indeterminate"],
    ["ne-true", { ne: ["1", 1] }, "deny-rule"],
    ["ne-same", { ne: [1, 1] }, "role"],
    ["eq-null", { eq: [null, null] }, "deny-rule"],
    ["eq-bool", { eq: [true, true] }, "deny-rule"],
    ["eq-bool-num", { eq: [true, 1] }, "role"],
    ["eq-str-num", { eq: ["1", 1] }, "role"],
    ["gt-str", { gt: ["2", 1] }, "role"],
    ["gt", { gt: [2, 1] }, "deny-rule"],
    ["gt-equal", { gt: [1, 1] }, "role"],
    ["gte", { gte: [1, 1] }, "deny-rule"],
    ["lt", { lt: [1, 2] }, "deny-rule"],
    ["lt-false", { lt: [2, 1] }, "role"],
    ["lte", { lte: [2, 2] }, "deny-rule"],
    ["lte-false", { lte: [3, 2] }, "role"],
    ["gt-missing", { gt: [M, 1] }, "deny-indeterminate"],
    ["lt-missing-right", { lt: [1, M] }, "deny-indeterminate"],
    ["in-true", { in: [1, [2, 1]] }, "deny-rule"],
    ["in-false", { in: [3, [2, 1]] }, "role"],
    ["in-strict", { in: ["1", [1]] }, "role"],
    ["in-missing-needle", { in: [M, [1]] }, "deny-indeterminate"],
    ["in-missing-item", { in: [3, [M, 1]] }, "deny-indeterminate"],
    ["in-hit-after-missing", { in: [1, [M, 1]] }, "deny-rule"],
    ["in-empty", { in: [1, []] }, "role"],
  ];

  it("follows Kleene logic for every operator", () => {
    for (const [name, when, expected] of table) {
      expect(outcome(when), name).toBe(expected);
    }
  });

  it("treats odd attribute values safely", () => {
    const attrs = {
      n: 5,
      inf: Number.POSITIVE_INFINITY,
      nan: Number.NaN,
      nul: null,
      undef: undefined,
    };
    const n = { ref: "resource.attributes.n" };
    const inf = { ref: "resource.attributes.inf" };
    const nan = { ref: "resource.attributes.nan" };
    const nul = { ref: "resource.attributes.nul" };
    const undef = { ref: "resource.attributes.undef" };
    expect(outcome({ gt: [n, 1] }, attrs)).toBe("deny-rule");
    expect(outcome({ gt: [inf, 1] }, attrs)).toBe("role");
    expect(outcome({ lt: [nan, 1] }, attrs)).toBe("role");
    expect(outcome({ exists: nul }, attrs)).toBe("deny-rule");
    expect(outcome({ eq: [nul, null] }, attrs)).toBe("deny-rule");
    expect(outcome({ exists: undef }, attrs)).toBe("role");
  });

  it("never reads the prototype chain", () => {
    const toStr = { ref: "resource.attributes.toString" };
    expect(outcome({ exists: toStr })).toBe("role");
    expect(outcome({ eq: [toStr, 1] })).toBe("deny-indeterminate");
    const inherited = Object.create({ x: 1 }) as Attrs;
    expect(outcome({ exists: { ref: "resource.attributes.x" } }, inherited)).toBe("role");
    const polluted = JSON.parse('{"__proto__":{"admin":true},"ownerId":"u1"}') as Attrs;
    expect(outcome({ exists: { ref: "resource.attributes.admin" } }, polluted)).toBe("role");
    expect(outcome({ exists: { ref: "resource.attributes.ownerId" } }, polluted)).toBe("deny-rule");
  });

  it("resolves subject, action, resource and context refs", () => {
    const request: Req = {
      subject: { id: "u1", roles: ["viewer"], attributes: { dept: "eng" } },
      action: "read",
      resource: { type: "doc" },
      context: { tenant: "t1" },
    };
    const check = (when: unknown): string => evaluate(denyWhen(when), request).reason;
    expect(check({ eq: [{ ref: "subject.attributes.dept" }, "eng"] })).toBe("deny-rule");
    expect(check({ eq: [{ ref: "context.tenant" }, "t1"] })).toBe("deny-rule");
    expect(check({ eq: [{ ref: "action" }, "read"] })).toBe("deny-rule");
    expect(check({ eq: [{ ref: "resource.type" }, "doc"] })).toBe("deny-rule");
    expect(check({ exists: { ref: "action.length" } })).toBe("role");
    expect(check({ exists: { ref: "subject.roles" } })).toBe("deny-rule");
    expect(outcome({ exists: { ref: "context.tenant" } })).toBe("role");
  });

  it("does not run strings as code", () => {
    const payload = "constructor.constructor('return 1')()";
    const when = { eq: [{ ref: "resource.attributes.x" }, payload] };
    expect(outcome(when, { x: payload })).toBe("deny-rule");
    expect(outcome(when, { x: "other" })).toBe("role");
    const code = { eval: ["1"] };
    expect(raises(() => denyWhen(code)).code).toBe("invalid_policy");
    const fn = { call: { ref: "subject.id" } };
    expect(raises(() => denyWhen(fn)).code).toBe("invalid_policy");
  });
});

describe("policy validation", () => {
  it("rejects dangerous and malformed refs", () => {
    const refs = ["subject.__proto__.x", "resource.constructor", "context.prototype"];
    refs.push("other.x", "subject.", "subject..x", "subject.a-b", "", "subject.a b", "x");
    for (const ref of refs) {
      const when = { eq: [{ ref }, 1] };
      expect(raises(() => denyWhen(when)).code, ref).toBe("invalid_policy");
    }
    expect(raises(() => denyWhen({ eq: [{ ref: 5 }, 1] })).code).toBe("invalid_policy");
    const long = { eq: [{ ref: `subject.${"a".repeat(300)}` }, 1] };
    expect(raises(() => denyWhen(long)).code).toBe("limit_exceeded");
  });

  it("limits condition depth to 32", () => {
    expect(outcome(nest(31))).toBe("role");
    expect(raises(() => denyWhen(nest(32))).code).toBe("limit_exceeded");
  });

  it("limits condition nodes", () => {
    const fits = { and: Array.from({ length: 4999 }, () => ({ exists: 0 })) };
    expect(outcome(fits)).toBe("deny-rule");
    const over = { and: Array.from({ length: 5001 }, () => ({ exists: 0 })) };
    expect(raises(() => denyWhen(over)).code).toBe("limit_exceeded");
  });

  it("limits in lists and strings", () => {
    const list = Array.from({ length: 1000 }, (_, i) => i);
    expect(outcome({ in: [999, list] })).toBe("deny-rule");
    const tooLong = Array.from({ length: 1001 }, (_, i) => i);
    expect(raises(() => denyWhen({ in: [1, tooLong] })).code).toBe("limit_exceeded");
    const text = { eq: ["x".repeat(1025), 1] };
    expect(raises(() => denyWhen(text)).code).toBe("limit_exceeded");
  });

  it("rejects malformed conditions", () => {
    const proto = JSON.parse('{"__proto__":[1,1]}') as unknown;
    const list: unknown[] = [null, "x", 5, [], {}, { eq: [1, 2], ne: [1, 2] }, { eq: [1] }];
    list.push({ eq: "x" }, { eq: [Number.NaN, 1] }, { eq: [Number.POSITIVE_INFINITY, 1] });
    list.push({ eq: [undefined, 1] }, { eq: [{ ref: "subject.id", x: 1 }, 1] }, { eq: [{}, 1] });
    list.push({ eq: [[], 1] }, { in: [1, 2] }, { in: 1 }, { in: [1] }, { and: [] }, { and: 1 });
    list.push({ or: [] }, { not: 1 }, { not: [] }, { exists: undefined }, { constructor: 1 });
    list.push({ nope: 1 }, proto, { and: [undefined] });
    for (const when of list) {
      expect(raises(() => denyWhen(when)).code, JSON.stringify(when)).toBe("invalid_policy");
    }
  });

  it("rejects malformed policies", () => {
    const list: unknown[] = [null, 5, [], "x", {}, { roles: [] }, { roles: {}, extra: 1 }];
    list.push({ roles: { "1a": { permissions: [] } } }, { roles: { "": { permissions: [] } } });
    list.push({ roles: { "a b": { permissions: [] } } });
    list.push({ roles: { ["x".repeat(65)]: { permissions: [] } } });
    list.push({ roles: { a: null } }, { roles: { a: [] } }, { roles: { a: {} } });
    list.push({ roles: { a: { permissions: "doc:read" } } });
    list.push({ roles: { a: { permissions: [], extra: 1 } } });
    list.push({ roles: {}, rules: {} }, { roles: {}, rules: [null] });
    for (const input of list) {
      expect(raises(() => pol(input)).code, JSON.stringify(input)).toBe("invalid_policy");
    }
  });

  it("rejects malformed rules", () => {
    const base = { id: "r", effect: "deny", resource: "doc", action: "read" };
    const variants: Array<Record<string, unknown>> = [
      { ...base, id: "" },
      { ...base, id: 5 },
      { ...base, id: "i".repeat(129) },
      { ...base, effect: "permit" },
      { ...base, resource: "Doc" },
      { ...base, resource: "*" },
      { ...base, action: "READ" },
      { ...base, action: 5 },
      { ...base, extra: 1 },
      { ...base, when: null },
    ];
    for (const rule of variants) {
      expect(raises(() => pol({ roles: {}, rules: [rule] })).code).toBe("invalid_policy");
    }
    const twice = pol({
      roles: {},
      rules: [
        { ...base, id: "a" },
        { ...base, id: "b" },
      ],
    });
    expect(twice.rules).toHaveLength(2);
    expect(raises(() => pol({ roles: {}, rules: [base, base] })).code).toBe("invalid_policy");
    const wildcard = pol({ roles: {}, rules: [{ ...base, action: "*" }] });
    expect(wildcard.rules[0]).toEqual({ ...base, action: "*", hasCondition: false });
  });

  it("enforces size limits", () => {
    const roles: Record<string, unknown> = {};
    for (let i = 0; i < 1001; i += 1) {
      roles[`r${i}`] = { permissions: [] };
    }
    expect(raises(() => pol({ roles })).code).toBe("limit_exceeded");
    const rule = { effect: "allow", resource: "doc", action: "read" };
    const rules = Array.from({ length: 1001 }, (_, i) => ({ ...rule, id: `r${i}` }));
    expect(raises(() => pol({ roles: {}, rules })).code).toBe("limit_exceeded");
    const wide = { roles: { a: { permissions: perms(0, 1001) } } };
    expect(raises(() => pol(wide)).code).toBe("limit_exceeded");
    const total = {
      roles: {
        a: { permissions: perms(0, 1000) },
        b: { permissions: perms(1000, 1000) },
        c: { permissions: perms(2000, 1) },
      },
    };
    expect(raises(() => pol(total)).code).toBe("limit_exceeded");
  });

  it("resists prototype pollution through role names", () => {
    const input = JSON.parse('{"roles":{"__proto__":{"permissions":["doc:read"]}}}') as unknown;
    expect(raises(() => pol(input)).code).toBe("invalid_policy");
    expect(({} as Attrs).permissions).toBeUndefined();
    expect(({} as Attrs).read).toBeUndefined();
  });
});

describe("evaluate input", () => {
  const policy = pol({ roles: VIEWER });
  const SUB = { id: "u1", roles: [] };
  const DOC = { type: "doc" };
  const bads: Array<[string, unknown]> = [
    ["null request", null],
    ["array request", []],
    ["no subject", { action: "read", resource: DOC }],
    ["id not string", { subject: { id: 1, roles: [] }, action: "read", resource: DOC }],
    ["roles not array", { subject: { id: "u", roles: "a" }, action: "read", resource: DOC }],
    ["role not string", { subject: { id: "u", roles: [1] }, action: "read", resource: DOC }],
    ["subject attrs", { subject: { ...SUB, attributes: [] }, action: "read", resource: DOC }],
    ["no resource", { subject: SUB, action: "read" }],
    ["resource id", { subject: SUB, action: "read", resource: { type: "doc", id: 5 } }],
    [
      "resource attrs",
      { subject: SUB, action: "read", resource: { type: "doc", attributes: "x" } },
    ],
    ["context", { subject: SUB, action: "read", resource: DOC, context: [] }],
    ["action star", { subject: SUB, action: "*", resource: DOC }],
    ["type Doc!", { subject: SUB, action: "read", resource: { type: "Doc!" } }],
    ["empty action", { subject: SUB, action: "", resource: DOC }],
    ["upper action", { subject: SUB, action: "Read", resource: DOC }],
    ["long action", { subject: SUB, action: "a".repeat(129), resource: DOC }],
    ["missing action", { subject: SUB, resource: DOC }],
  ];

  it("throws invalid_request for malformed requests", () => {
    for (const [name, request] of bads) {
      expect(raises(() => evaluate(policy, request as Req)).code, name).toBe("invalid_request");
    }
  });

  it("limits subject roles", () => {
    const roles = Array.from({ length: 1001 }, () => "viewer");
    const request = { subject: { id: "u1", roles }, action: "read", resource: DOC };
    expect(raises(() => evaluate(policy, request)).code).toBe("limit_exceeded");
  });

  it("accepts optional fields", () => {
    const request: Req = {
      subject: { id: "u1", roles: ["viewer"], attributes: {} },
      action: "read",
      resource: { type: "doc", id: "d1", attributes: {} },
      context: {},
    };
    expect(evaluate(policy, request)).toEqual(ok);
  });

  it("rejects policies not created by definePolicy", () => {
    const fake: rbac.Policy = { roles: new Map(), rules: [] };
    expect(raises(() => evaluate(fake, req([], "read"))).code).toBe("invalid_request");
    const nothing = null as unknown as rbac.Policy;
    expect(raises(() => evaluate(nothing, req([], "read"))).code).toBe("invalid_request");
    expect(raises(() => exportMatrix(fake)).code).toBe("invalid_policy");
  });

  it("rejects a non-function onDecision", () => {
    const options = { onDecision: "x" as unknown as () => void };
    expect(raises(() => evaluate(policy, req([], "read"), options)).code).toBe("invalid_request");
  });
});

describe("onDecision", () => {
  const rule = { id: "d1", effect: "deny", resource: "doc", action: "write" };
  const policy = pol({ roles: VIEWER, rules: [rule] });
  const request: Req = {
    subject: { id: "user-77", roles: ["viewer"], attributes: { token: "secret-value" } },
    action: "read",
    resource: { type: "doc", id: "d-1", attributes: { owner: "secret-owner" } },
    context: { ip: "secret-ip" },
  };

  it("reports only decision data and never attribute values", () => {
    const events: rbac.DecisionEvent[] = [];
    const onDecision = (event: rbac.DecisionEvent): void => {
      events.push(event);
    };
    evaluate(policy, request, { onDecision });
    evaluate(policy, { ...request, action: "write" }, { onDecision });
    expect(events).toHaveLength(2);
    expect(Object.keys(events[0] ?? {}).sort()).toEqual([
      "action",
      "allowed",
      "reason",
      "resourceType",
    ]);
    expect(events[1]).toEqual({
      allowed: false,
      reason: "deny-rule",
      ruleId: "d1",
      action: "write",
      resourceType: "doc",
    });
    const text = JSON.stringify(events);
    for (const secret of ["secret-value", "secret-owner", "secret-ip", "user-77", "d-1"]) {
      expect(text).not.toContain(secret);
    }
  });

  it("ignores observer failures", () => {
    const onDecision = (): void => {
      throw new Error("boom");
    };
    expect(evaluate(policy, request, { onDecision })).toEqual(ok);
  });

  it("is not called for invalid requests", () => {
    let calls = 0;
    const onDecision = (): void => {
      calls += 1;
    };
    const invalid = { ...request, action: "*" };
    expect(raises(() => evaluate(policy, invalid, { onDecision })).code).toBe("invalid_request");
    expect(calls).toBe(0);
  });
});

describe("matrix export", () => {
  const policy = pol({
    roles: {
      editor: { permissions: ["doc:write", "doc:read"] },
      auditor: { permissions: ["log:read"] },
      admin: { permissions: ["doc:*"], inherits: ["editor"] },
    },
  });

  it("exports sorted roles, permissions and effective grants", () => {
    expect(exportMatrix(policy)).toEqual({
      roles: ["admin", "auditor", "editor"],
      permissions: ["doc:*", "doc:read", "doc:write", "log:read"],
      grants: {
        admin: ["doc:*", "doc:read", "doc:write"],
        auditor: ["log:read"],
        editor: ["doc:read", "doc:write"],
      },
    });
  });

  it("renders a byte-exact CSV golden", () => {
    const expected = [
      "role,doc:*,doc:read,doc:write,log:read",
      "admin,x,x,x,",
      "auditor,,,,x",
      "editor,,x,x,",
      "",
    ].join("\r\n");
    expect(matrixToCsv(exportMatrix(policy))).toBe(expected);
  });

  it("renders a Markdown golden", () => {
    const expected = [
      "| role | doc:* | doc:read | doc:write | log:read |",
      "| --- | --- | --- | --- | --- |",
      "| admin | x | x | x |  |",
      "| auditor |  |  |  | x |",
      "| editor |  | x | x |  |",
      "",
    ].join("\n");
    expect(matrixToMarkdown(exportMatrix(policy))).toBe(expected);
  });

  it("renders an empty policy", () => {
    const empty = exportMatrix(pol({ roles: {} }));
    expect(matrixToCsv(empty)).toBe("role\r\n");
    expect(matrixToMarkdown(empty)).toBe("| role |\n| --- |\n");
  });
});

describe("CSV and Markdown hardening", () => {
  const hand = (role: string, permission = "doc:read"): rbac.PermissionMatrix => ({
    roles: [role],
    permissions: [permission],
    grants: { [role]: [permission] },
  });

  it("guards against CSV injection", () => {
    expect(matrixToCsv(hand("=cmd"))).toBe("role,doc:read\r\n'=cmd,x\r\n");
    expect(matrixToCsv(hand("+a"))).toBe("role,doc:read\r\n'+a,x\r\n");
    expect(matrixToCsv(hand("-a"))).toBe("role,doc:read\r\n'-a,x\r\n");
    expect(matrixToCsv(hand("@a"))).toBe("role,doc:read\r\n'@a,x\r\n");
    expect(matrixToCsv(hand("\ta"))).toBe("role,doc:read\r\n'\ta,x\r\n");
    expect(matrixToCsv(hand("\ra"))).toBe('role,doc:read\r\n"\'\ra",x\r\n');
    expect(matrixToCsv(hand("a", "=1+1"))).toBe("role,'=1+1\r\na,x\r\n");
  });

  it("quotes cells per RFC 4180", () => {
    expect(matrixToCsv(hand('a,"b'))).toBe('role,doc:read\r\n"a,""b",x\r\n');
    expect(matrixToCsv(hand("a\nb"))).toBe('role,doc:read\r\n"a\nb",x\r\n');
  });

  it("escapes Markdown cells", () => {
    expect(matrixToMarkdown(hand("a|b"))).toContain("| a\\|b | x |");
    expect(matrixToMarkdown(hand("a\\b"))).toContain("| a\\\\b | x |");
    expect(matrixToMarkdown(hand("a\r\nb"))).toContain("| a b | x |");
  });

  it("treats missing grants as empty and ignores inherited keys", () => {
    const matrix = { roles: ["toString"], permissions: ["doc:read"], grants: {} };
    expect(matrixToCsv(matrix)).toBe("role,doc:read\r\ntoString,\r\n");
    expect(matrixToMarkdown(matrix)).toBe("| role | doc:read |\n| --- | --- |\n| toString |  |\n");
  });

  it("rejects malformed and oversized matrices", () => {
    const good = { roles: ["a"], permissions: ["doc:read"], grants: { a: ["doc:read"] } };
    const invalid: unknown[] = [null, [], { ...good, roles: "a" }, { ...good, roles: [1] }];
    invalid.push({ ...good, permissions: undefined }, { ...good, grants: null });
    invalid.push({ ...good, grants: { a: "doc:read" } }, { ...good, grants: { a: [1] } });
    for (const matrix of invalid) {
      const m = matrix as rbac.PermissionMatrix;
      expect(raises(() => matrixToCsv(m)).code).toBe("invalid_policy");
      expect(raises(() => matrixToMarkdown(m)).code).toBe("invalid_policy");
    }
    const roles = Array.from({ length: 1001 }, () => "a");
    const permissions = Array.from({ length: 2001 }, () => "p:r");
    const long = { ...good, roles: ["a".repeat(1025)] };
    for (const matrix of [{ ...good, roles }, { ...good, permissions }, long]) {
      expect(raises(() => matrixToCsv(matrix)).code).toBe("limit_exceeded");
      expect(raises(() => matrixToMarkdown(matrix)).code).toBe("limit_exceeded");
    }
  });
});

describe("PolicyError", () => {
  it("carries a code and problems", () => {
    const error = new PolicyError("invalid_policy", "bad");
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe("PolicyError");
    expect(error.code).toBe("invalid_policy");
    expect(error.problems).toEqual(["bad"]);
    expect(new PolicyError("limit_exceeded", "m", ["p1", "p2"]).problems).toEqual(["p1", "p2"]);
  });

  it("never echoes more than 200 characters of input", () => {
    const huge = "x".repeat(5000);
    const error = raises(() => pol({ roles: { [huge]: { permissions: [] } } }));
    expect(error.message.length).toBeLessThanOrEqual(200);
    expect(error.message).not.toContain(huge);
    const long = new PolicyError("invalid_request", huge, [huge]);
    expect(long.message.length).toBe(200);
    expect(long.problems[0]?.length).toBe(200);
  });

  it("describes non-string input by type", () => {
    const nul = { roles: { a: { permissions: [null] } } };
    expect(raises(() => pol(nul)).message).toContain("null");
    const arr = { roles: { a: { permissions: [[]] } } };
    expect(raises(() => pol(arr)).message).toContain("array");
    const num = { roles: { a: { permissions: [5] } } };
    expect(raises(() => pol(num)).message).toContain("number");
  });
});
