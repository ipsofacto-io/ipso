export const PAGE_LIMIT = 100;

const EDR_ID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

// verdictRef is the EDR id, or the slug when the body has no EDR id.
// The registry uuid is not a verdict filter.
export function verdictRef(decision) {
  const body = decision && decision.body;
  if (!body || typeof body !== "object" || Array.isArray(body)) return "";
  if (typeof body.id === "string" && EDR_ID.test(body.id)) return body.id;
  if (typeof body.slug === "string" && SLUG.test(body.slug)) return body.slug;
  return "";
}

function envMatches(value, env) {
  if (typeof value !== "string" || typeof env !== "string" || value.length === 0 || value.length > 256) return false;
  let folded = "";
  for (const char of value) {
    if (char > "~") return false;
    folded += char >= "A" && char <= "Z" ? char.toLowerCase() : char;
  }
  return folded === env;
}

// latestResults keeps the first result of each check index for the mapped env.
// The verdict list is newest first, so the first matching row is the latest.
export function latestResults(items, env) {
  const seen = new Set();
  const results = [];
  if (!Array.isArray(items)) return results;
  for (const item of items) {
    if (!item || typeof item.check_index !== "number" || !Number.isInteger(item.check_index)) continue;
    if (typeof item.result !== "string" || !envMatches(item.env, env)) continue;
    if (seen.has(item.check_index)) continue;
    seen.add(item.check_index);
    results.push({ index: item.check_index, result: item.result });
  }
  return results;
}

export function declaredChecks(decision) {
  const checks = decision && decision.body && decision.body.checks;
  if (!Array.isArray(checks)) return null;
  return checks.length;
}

function repoPasses(results, declared) {
  if (!Array.isArray(results) || results.length === 0) return false;
  if (!results.every((item) => item.result === "pass")) return false;
  if (declared === null || declared === 0) return true;
  if (declared > PAGE_LIMIT) return false;
  for (let index = 0; index < declared; index += 1) {
    if (!results.some((item) => item.index === index)) return false;
  }
  return true;
}

export function countPassing(groups) {
  let passing = 0;
  for (const group of groups) {
    if (group.perRepo.length > 0 && group.perRepo.every((results) => repoPasses(results, group.declared))) passing += 1;
  }
  return passing;
}

export function pageIsFull(items) {
  return Array.isArray(items) && items.length >= PAGE_LIMIT;
}
