import { renderCard, REFUSED } from "./card.mjs";
import { countPassing, declaredChecks, latestResults, pageIsFull, verdictRef } from "./coverage.mjs";
import { createClient } from "./client.mjs";
import { NOT_MAPPED, SCOPE_INCOMPLETE, mapEntity } from "./map.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function show(decision) {
  if (!decision || typeof decision.id !== "string" || !UUID.test(decision.id)) return null;
  const body = decision.body && typeof decision.body === "object" && !Array.isArray(decision.body) ? decision.body : {};
  const slug = typeof body.slug === "string" && SLUG.test(body.slug) ? body.slug : "";
  let title = "";
  if (typeof body.title === "string" && body.title.length > 0 && body.title.length <= 200 && !/[\r\n]/.test(body.title)) {
    title = body.title;
  }
  return { id: decision.id, slug, title };
}

function containsToken(value, token) {
  if (typeof value === "string") return value.includes(token);
  if (!value || typeof value !== "object") return false;
  return Object.values(value).some((item) => containsToken(item, token));
}

function seal(view, token) {
  if (containsToken(view, token)) return { state: "error", message: REFUSED };
  return view;
}

async function load(client, entity, token) {
  let mapped = mapEntity(entity);
  if (mapped.kind === "needs-scopes") {
    mapped = mapEntity(entity, await client.scopes());
  }
  if (mapped.kind === "unmapped") return seal({ state: "unmapped", message: NOT_MAPPED }, token);
  if (mapped.kind === "error") return seal({ state: "error", message: mapped.message }, token);

  const rows = new Map();
  let incomplete = false;
  for (const repo of mapped.repos) {
    const answer = await read(client.resolve(repo, mapped.env, mapped.paths));
    if (!answer) {
      incomplete = true;
      break;
    }
    if (!Array.isArray(answer.decisions)) throw Object.assign(new Error("refused"), { code: "refused" });
    let stopped = false;
    for (const decision of answer.decisions) {
      const shown = show(decision);
      if (!shown) continue;
      if (!rows.has(shown.id)) rows.set(shown.id, { shown, perRepo: [], declared: null });
      const row = rows.get(shown.id);
      const declared = declaredChecks(decision);
      if (declared !== null && (row.declared === null || declared > row.declared)) row.declared = declared;
      if (declared !== null && declared > 100) incomplete = true;
      const ref = verdictRef(decision);
      if (!ref) {
        row.perRepo.push([]);
        continue;
      }
      const page = await read(client.verdicts(repo, ref));
      if (!page) {
        incomplete = true;
        stopped = true;
        break;
      }
      if (!Array.isArray(page.verdicts)) throw Object.assign(new Error("refused"), { code: "refused" });
      if (pageIsFull(page.verdicts)) incomplete = true;
      row.perRepo.push(latestResults(page.verdicts, mapped.env));
    }
    if (stopped) break;
  }

  const ordered = [...rows.values()].sort((a, b) => (a.shown.slug || a.shown.id).localeCompare(b.shown.slug || b.shown.id));
  const decisions = ordered.map((row) => row.shown);
  if (incomplete) return seal({ state: "incomplete", decisions }, token);
  return seal(
    {
      state: "ok",
      passing: countPassing(ordered),
      total: decisions.length,
      decisions,
    },
    token,
  );
}

async function read(pending) {
  try {
    return await pending;
  } catch (err) {
    if (err && err.code === "budget") return null;
    throw err;
  }
}

export function createHandler({ baseUrl, token, fetch: fetchImpl }) {
  const api = createClient({ baseUrl, token, fetch: fetchImpl });
  return async function handle(entity) {
    try {
      return await load(api.open(), entity, token);
    } catch (err) {
      const view = err && err.code === "incomplete" ? { state: "error", message: SCOPE_INCOMPLETE } : { state: "error", message: REFUSED };
      return seal(view, token);
    }
  };
}

export { renderCard };
