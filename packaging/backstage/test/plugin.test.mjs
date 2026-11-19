import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { INCOMPLETE, REFUSED, renderCard } from "../lib/card.mjs";
import { createHandler } from "../lib/handler.mjs";
import { NOT_MAPPED, OUTSIDE, SCOPE_INCOMPLETE } from "../lib/map.mjs";

const TOKEN = "ipso-person-token-0123456789";
const BASE = "https://ipso.example";
const TLS = "01M7TE79FQCYXVNBJVGNKY9TDA";
const DISK = "01M7TE79FQCYXVNBJVGNKY9TDB";
const TLS_UUID = "11111111-1111-4111-8111-111111111111";
const DISK_UUID = "22222222-2222-4222-8222-222222222222";
const ORG = "10000000-0000-4000-8000-000000000001";
const PAY = "10000000-0000-4000-8000-000000000002";
const BILL = "10000000-0000-4000-8000-000000000003";
const REPO_PAY = "10000000-0000-4000-8000-000000000004";
const REPO_OTHER = "10000000-0000-4000-8000-000000000005";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

function entityFromCatalog(text) {
  const annotations = {};
  let inAnnotations = false;
  for (const line of text.split("\n")) {
    if (line === "  annotations:") {
      inAnnotations = true;
      continue;
    }
    if (!inAnnotations) continue;
    if (!line.startsWith("    ")) break;
    const split = line.indexOf(":");
    annotations[line.slice(4, split)] = line.slice(split + 1).trim();
  }
  return { kind: "Component", metadata: { name: "payments", annotations } };
}

function sampleEntity() {
  return entityFromCatalog(readFileSync(join(root, "catalog-info.yaml"), "utf8"));
}

function decision(id, edr, slug, title) {
  return { id, version: 1, body: { id: edr, slug, title, owner: "team:core" } };
}

function api(route) {
  const calls = [];
  const fetch = async (url, init) => {
    const target = new URL(url);
    calls.push({
      method: init.method,
      path: target.pathname,
      search: target.search,
      body: init.body,
      authorization: init.headers.authorization,
      redirect: init.redirect,
    });
    const result = await route(target, init);
    return {
      ok: result.status === 200,
      status: result.status,
      json: async () => result.body,
    };
  };
  return { fetch, calls };
}

function noToken(view) {
  assert.equal(JSON.stringify(view).includes(TOKEN), false);
  assert.equal(JSON.stringify(view).includes("team:core"), false);
  assert.equal(JSON.stringify(renderCard(view)).includes(TOKEN), false);
}

test("an entity with no env does not call the API", async () => {
  const { fetch, calls } = api(() => {
    throw new Error("called");
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle({ metadata: { annotations: { "ipsofacto.io/repo": "acme/payments" } } });
  assert.equal(view.state, "unmapped");
  assert.equal(renderCard(view), NOT_MAPPED);
  assert.equal(calls.length, 0);
  noToken(view);
});

test("a sample repo entity renders its decisions and coverage", async () => {
  const { fetch, calls } = api((url) => {
    if (url.pathname === "/v1/resolve") {
      return { status: 200, body: { decisions: [decision(TLS_UUID, TLS, "use-tls", "Use TLS")] } };
    }
    if (url.pathname === "/v1/verdicts") {
      assert.equal(url.searchParams.get("decision"), TLS);
      assert.equal(url.searchParams.get("repo"), "acme/payments");
      return { status: 200, body: { verdicts: [{ check_index: 0, result: "pass", env: "prod" }] } };
    }
    throw new Error(url.pathname);
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle(sampleEntity());
  assert.equal(view.state, "ok");
  assert.equal(view.passing, 1);
  assert.equal(view.total, 1);
  assert.deepEqual(view.decisions, [{ id: TLS_UUID, slug: "use-tls", title: "Use TLS" }]);
  assert.equal(renderCard(view), "1 of 1 decisions passing\nuse-tls Use TLS");
  const resolve = calls.find((call) => call.path === "/v1/resolve");
  assert.equal(resolve.authorization, `Bearer ${TOKEN}`);
  assert.equal(resolve.redirect, "error");
  assert.deepEqual(JSON.parse(resolve.body), { repo: "acme/payments", env: "prod", paths: ["ipso-catalog"] });
  assert.equal(calls.some((call) => call.path === "/v1/scopes"), false);
  assert.equal(resolve.body.includes(TOKEN), false);
  noToken(view);
});

test("a project slug is the repo when the repo annotation is absent", async () => {
  const entity = sampleEntity();
  delete entity.metadata.annotations["ipsofacto.io/repo"];
  const { fetch, calls } = api((url) => {
    if (url.pathname === "/v1/resolve") {
      return { status: 200, body: { decisions: [decision(TLS_UUID, TLS, "use-tls", "Use TLS")] } };
    }
    return { status: 200, body: { verdicts: [{ check_index: 0, result: "pass", env: "prod" }] } };
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle(entity);
  assert.equal(view.passing, 1);
  assert.equal(JSON.parse(calls[0].body).repo, "acme/payments");
});

test("a path the control plane rejects does not call resolve", async () => {
  for (const paths of [".", "..", "/abs", "a//b", "a/../b", "a/./b"]) {
    const entity = sampleEntity();
    entity.metadata.annotations["ipsofacto.io/paths"] = paths;
    const { fetch, calls } = api(() => ({ status: 200, body: { decisions: [] } }));
    const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
    const view = await handle(entity);
    assert.equal(view.state, "error");
    assert.equal(calls.length, 0, paths);
  }
});

test("a decision with no EDR id and no slug does not pass and stays in the total", async () => {
  const { fetch } = api(() => ({
    status: 200,
    body: { decisions: [{ id: TLS_UUID, version: 1, body: { title: "Untitled", owner: "team:core" } }], verdicts: [] },
  }));
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle(sampleEntity());
  assert.equal(view.passing, 0);
  assert.equal(view.total, 1);
  assert.equal(view.decisions[0].slug, "");
  assert.equal(JSON.stringify(view).includes("team:core"), false);
});

test("a named path list is sent as given", async () => {
  const entity = sampleEntity();
  entity.metadata.annotations["ipsofacto.io/paths"] = "src/main.go, README.md";
  const { fetch, calls } = api(() => ({ status: 200, body: { decisions: [], verdicts: [] } }));
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle(entity);
  assert.deepEqual(JSON.parse(calls[0].body).paths, ["src/main.go", "README.md"]);
  assert.equal(view.passing, 0);
  assert.equal(view.total, 0);
});

test("a repo outside the named service does not call resolve", async () => {
  const { fetch, calls } = api((url) => {
    assert.equal(url.pathname, "/v1/scopes");
    return {
      status: 200,
      body: {
        scopes: [
          { id: ORG, parent_id: null, kind: "org", selector: "acme" },
          { id: PAY, parent_id: ORG, kind: "service", selector: "payments" },
          { id: BILL, parent_id: ORG, kind: "service", selector: "billing" },
          { id: REPO_OTHER, parent_id: BILL, kind: "repo", selector: "acme/other" },
        ],
      },
    };
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle({
    metadata: {
      annotations: {
        "ipsofacto.io/service": "payments",
        "ipsofacto.io/repo": "acme/other",
        "ipsofacto.io/env": "prod",
      },
    },
  });
  assert.equal(view.state, "error");
  assert.equal(view.message, OUTSIDE);
  assert.equal(renderCard(view), OUTSIDE);
  assert.equal(calls.some((call) => call.path === "/v1/resolve"), false);
  noToken(view);
});

test("a service uses every repo under it and a fail on one repo does not pass", async () => {
  const { fetch, calls } = api((url, init) => {
    if (url.pathname === "/v1/scopes") {
      return {
        status: 200,
        body: {
          scopes: [
            { id: ORG, parent_id: null, kind: "org", selector: "acme" },
            { id: PAY, parent_id: ORG, kind: "service", selector: "payments" },
            { id: REPO_PAY, parent_id: PAY, kind: "repo", selector: "acme/payments" },
            { id: REPO_OTHER, parent_id: PAY, kind: "repo", selector: "acme/billing" },
          ],
        },
      };
    }
    if (url.pathname === "/v1/verdicts") {
      const repo = url.searchParams.get("repo");
      return { status: 200, body: { verdicts: [{ check_index: 0, result: repo === "acme/payments" ? "pass" : "fail", env: "prod" }] } };
    }
    assert.equal(init.method, "POST");
    return { status: 200, body: { decisions: [decision(TLS_UUID, TLS, "use-tls", "Use TLS")] } };
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle({
    metadata: { annotations: { "ipsofacto.io/service": "payments", "ipsofacto.io/env": "prod" } },
  });
  const repos = calls.filter((call) => call.path === "/v1/resolve").map((call) => JSON.parse(call.body).repo);
  assert.deepEqual(repos, ["acme/billing", "acme/payments"]);
  assert.equal(view.passing, 0);
  assert.equal(view.total, 1);
  assert.equal(renderCard(view), "0 of 1 decisions passing\nuse-tls Use TLS");
});

test("a decision that one repo does not return can still pass", async () => {
  const { fetch, calls } = api((url, init) => {
    if (url.pathname === "/v1/scopes") {
      return {
        status: 200,
        body: {
          scopes: [
            { id: ORG, parent_id: null, kind: "org", selector: "acme" },
            { id: PAY, parent_id: ORG, kind: "service", selector: "payments" },
            { id: REPO_PAY, parent_id: PAY, kind: "repo", selector: "acme/payments" },
            { id: REPO_OTHER, parent_id: PAY, kind: "repo", selector: "acme/billing" },
          ],
        },
      };
    }
    if (url.pathname === "/v1/verdicts") {
      return { status: 200, body: { verdicts: [{ check_index: 0, result: "pass", env: "prod" }] } };
    }
    const repo = JSON.parse(init.body).repo;
    const decisions = repo === "acme/payments" ? [decision(TLS_UUID, TLS, "use-tls", "Use TLS")] : [];
    return { status: 200, body: { decisions } };
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle({
    metadata: { annotations: { "ipsofacto.io/service": "payments", "ipsofacto.io/env": "prod" } },
  });
  assert.equal(calls.filter((call) => call.path === "/v1/verdicts").length, 1);
  assert.equal(view.passing, 1);
  assert.equal(view.total, 1);
});

test("an empty verdict page on one repo does not pass", async () => {
  const { fetch } = api((url) => {
    if (url.pathname === "/v1/scopes") {
      return {
        status: 200,
        body: {
          scopes: [
            { id: ORG, parent_id: null, kind: "org", selector: "acme" },
            { id: PAY, parent_id: ORG, kind: "service", selector: "payments" },
            { id: REPO_PAY, parent_id: PAY, kind: "repo", selector: "acme/payments" },
            { id: REPO_OTHER, parent_id: PAY, kind: "repo", selector: "acme/billing" },
          ],
        },
      };
    }
    if (url.pathname === "/v1/verdicts") {
      const repo = url.searchParams.get("repo");
      const verdicts = repo === "acme/payments" ? [{ check_index: 0, result: "pass", env: "prod" }] : [];
      return { status: 200, body: { verdicts } };
    }
    return { status: 200, body: { decisions: [decision(TLS_UUID, TLS, "use-tls", "Use TLS")] } };
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle({
    metadata: { annotations: { "ipsofacto.io/service": "payments", "ipsofacto.io/env": "prod" } },
  });
  assert.equal(view.passing, 0);
  assert.equal(view.total, 1);
});

test("a missing check index does not pass", async () => {
  const body = { id: TLS, slug: "use-tls", title: "Use TLS", checks: [{}, {}], owner: "team:core" };
  const { fetch } = api(() => ({
    status: 200,
    body: { decisions: [{ id: TLS_UUID, version: 1, body }], verdicts: [{ check_index: 0, result: "pass", env: "prod" }] },
  }));
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle(sampleEntity());
  assert.equal(view.state, "ok");
  assert.equal(view.passing, 0);
  assert.equal(view.total, 1);
  assert.equal(JSON.stringify(view).includes("team:core"), false);
});

test("a card stops at the call budget", async () => {
  const scopes = [
    { id: ORG, parent_id: null, kind: "org", selector: "acme" },
    { id: PAY, parent_id: ORG, kind: "service", selector: "payments" },
  ];
  for (let index = 0; index < 30; index += 1) {
    scopes.push({
      id: `10000000-0000-4000-8000-${String(100 + index).padStart(12, "0")}`,
      parent_id: PAY,
      kind: "repo",
      selector: `acme/r${index}`,
    });
  }
  const { fetch, calls } = api((url) => {
    if (url.pathname === "/v1/scopes") return { status: 200, body: { scopes } };
    if (url.pathname === "/v1/verdicts") return { status: 200, body: { verdicts: [{ check_index: 0, result: "pass", env: "prod" }] } };
    return { status: 200, body: { decisions: [decision(TLS_UUID, TLS, "use-tls", "Use TLS")] } };
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle({
    metadata: { annotations: { "ipsofacto.io/service": "payments", "ipsofacto.io/env": "prod" } },
  });
  assert.equal(calls.length, 20);
  assert.equal(view.state, "incomplete");
  assert.equal(view.passing, undefined);
  assert.equal(renderCard(view).includes(INCOMPLETE), true);
  assert.equal(renderCard(view).includes(" of "), false);
});

test("a second card starts its call budget again", async () => {
  const { fetch, calls } = api(() => ({
    status: 200,
    body: { decisions: [decision(TLS_UUID, TLS, "use-tls", "Use TLS")], verdicts: [{ check_index: 0, result: "pass", env: "prod" }] },
  }));
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const first = await handle(sampleEntity());
  const afterFirst = calls.length;
  const second = await handle(sampleEntity());
  assert.equal(first.passing, 1);
  assert.equal(second.passing, 1);
  assert.equal(calls.length, afterFirst * 2);
});

test("a service and a repo annotation resolve only that repo", async () => {
  const { fetch, calls } = api((url) => {
    if (url.pathname === "/v1/scopes") {
      return {
        status: 200,
        body: {
          scopes: [
            { id: ORG, parent_id: null, kind: "org", selector: "acme" },
            { id: PAY, parent_id: ORG, kind: "service", selector: "payments" },
            { id: REPO_PAY, parent_id: PAY, kind: "repo", selector: "acme/payments" },
            { id: REPO_OTHER, parent_id: PAY, kind: "repo", selector: "acme/billing" },
          ],
        },
      };
    }
    if (url.pathname === "/v1/verdicts") return { status: 200, body: { verdicts: [{ check_index: 0, result: "pass", env: "prod" }] } };
    return { status: 200, body: { decisions: [decision(TLS_UUID, TLS, "use-tls", "Use TLS")] } };
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle({
    metadata: {
      annotations: {
        "ipsofacto.io/service": "payments",
        "ipsofacto.io/repo": "acme/payments",
        "ipsofacto.io/env": "prod",
      },
    },
  });
  const repos = calls.filter((call) => call.path === "/v1/resolve").map((call) => JSON.parse(call.body).repo);
  assert.deepEqual(repos, ["acme/payments"]);
  assert.equal(view.passing, 1);
});

test("a newer verdict for another env does not count", async () => {
  const { fetch } = api((url) => {
    if (url.pathname === "/v1/verdicts") {
      return {
        status: 200,
        body: {
          verdicts: [
            { check_index: 0, result: "fail", env: "stage" },
            { check_index: 0, result: "pass", env: "prod" },
          ],
        },
      };
    }
    return { status: 200, body: { decisions: [decision(TLS_UUID, TLS, "use-tls", "Use TLS")] } };
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle(sampleEntity());
  assert.equal(view.passing, 1);
  assert.equal(view.total, 1);
});

test("a passing verdict and a newer failure are counted apart", async () => {
  const { fetch } = api((url) => {
    if (url.pathname === "/v1/resolve") {
      return {
        status: 200,
        body: {
          decisions: [
            decision(TLS_UUID, TLS, "use-tls", "Use TLS"),
            decision(DISK_UUID, DISK, "encrypt-disk", "Encrypt disk"),
          ],
        },
      };
    }
    if (url.searchParams.get("decision") === TLS) {
      return { status: 200, body: { verdicts: [{ check_index: 0, result: "pass", env: "prod" }] } };
    }
    return {
      status: 200,
      body: {
        verdicts: [
          { check_index: 0, result: "fail", env: "prod" },
          { check_index: 0, result: "pass", env: "prod" },
        ],
      },
    };
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle(sampleEntity());
  assert.equal(view.passing, 1);
  assert.equal(view.total, 2);
  assert.equal(renderCard(view), "1 of 2 decisions passing\nencrypt-disk Encrypt disk\nuse-tls Use TLS");
  noToken(view);
});

test("a full verdict page shows no percentage", async () => {
  const verdicts = Array.from({ length: 100 }, (_, index) => ({ check_index: index, result: "pass", env: "prod" }));
  const { fetch } = api((url) => {
    if (url.pathname === "/v1/resolve") {
      return { status: 200, body: { decisions: [decision(TLS_UUID, TLS, "use-tls", "Use TLS")] } };
    }
    return { status: 200, body: { verdicts } };
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle(sampleEntity());
  assert.equal(view.state, "incomplete");
  assert.equal(view.passing, undefined);
  assert.equal(renderCard(view).includes(INCOMPLETE), true);
  assert.equal(renderCard(view).includes("use-tls Use TLS"), true);
  assert.equal(renderCard(view).includes(" of "), false);
  noToken(view);
});

test("a scope on a later page is still found", async () => {
  const { fetch, calls } = api((url) => {
    if (url.pathname === "/v1/scopes") {
      if (!url.searchParams.get("before")) {
        return {
          status: 200,
          body: {
            scopes: Array.from({ length: 100 }, (_, index) => ({
              id: `20000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
              parent_id: null,
              kind: "org",
              selector: `o${index}`,
            })),
          },
        };
      }
      return {
        status: 200,
        body: {
          scopes: [
            { id: ORG, parent_id: null, kind: "org", selector: "acme" },
            { id: PAY, parent_id: ORG, kind: "service", selector: "payments" },
            { id: REPO_PAY, parent_id: PAY, kind: "repo", selector: "acme/payments" },
          ],
        },
      };
    }
    if (url.pathname === "/v1/verdicts") return { status: 200, body: { verdicts: [{ check_index: 0, result: "pass", env: "prod" }] } };
    return { status: 200, body: { decisions: [decision(TLS_UUID, TLS, "use-tls", "Use TLS")] } };
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle({
    metadata: { annotations: { "ipsofacto.io/service": "payments", "ipsofacto.io/env": "prod" } },
  });
  assert.equal(calls.filter((call) => call.path === "/v1/scopes").length, 2);
  assert.equal(view.passing, 1);
});

test("twenty full scope pages do not call resolve", async () => {
  const { fetch, calls } = api((url) => {
    assert.equal(url.pathname, "/v1/scopes");
    return {
      status: 200,
      body: {
        scopes: Array.from({ length: 100 }, (_, index) => ({
          id: `10000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
          parent_id: null,
          kind: "org",
          selector: `o${index}`,
        })),
      },
    };
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle({
    metadata: { annotations: { "ipsofacto.io/service": "payments", "ipsofacto.io/env": "prod" } },
  });
  assert.equal(calls.length, 20);
  assert.equal(view.state, "error");
  assert.equal(view.message, SCOPE_INCOMPLETE);
  noToken(view);
});

test("a base URL that is not https is refused before a request", () => {
  const fetch = () => {
    throw new Error("called");
  };
  assert.throws(() => createHandler({ baseUrl: "http://example.com", token: TOKEN, fetch }), { message: "request refused" });
  assert.throws(() => createHandler({ baseUrl: "https://user:pass@ipso.example", token: TOKEN, fetch }), { message: "request refused" });
  const handle = createHandler({ baseUrl: "http://127.0.0.1:9", token: TOKEN, fetch });
  return handle({ metadata: { annotations: {} } }).then((view) => {
    assert.equal(view.state, "unmapped");
  });
});

test("a redirect is not followed and the token stays out of the card", async () => {
  const seen = [];
  const server = createServer((req, res) => {
    seen.push(req.url);
    res.writeHead(302, { location: `http://evil.example/steal?t=${TOKEN}` });
    res.end("no");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    const handle = createHandler({ baseUrl: `http://127.0.0.1:${port}`, token: TOKEN, fetch });
    const view = await handle(sampleEntity());
    assert.equal(view.state, "error");
    assert.equal(view.message, REFUSED);
    assert.equal(renderCard(view).includes("evil.example"), false);
    noToken(view);
    assert.deepEqual(seen, ["/v1/resolve"]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("a title that is the token is not returned", async () => {
  const { fetch } = api((url) => {
    if (url.pathname === "/v1/resolve") {
      return { status: 200, body: { decisions: [decision(TLS_UUID, TLS, "use-tls", TOKEN)] } };
    }
    return { status: 200, body: { verdicts: [{ check_index: 0, result: "pass", env: "prod" }] } };
  });
  const handle = createHandler({ baseUrl: BASE, token: TOKEN, fetch });
  const view = await handle(sampleEntity());
  assert.equal(view.state, "error");
  assert.equal(view.message, REFUSED);
  noToken(view);
});
