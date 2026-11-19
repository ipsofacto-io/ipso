const ENV = "ipsofacto.io/env";
const REPO = "ipsofacto.io/repo";
const SERVICE = "ipsofacto.io/service";
const PATHS = "ipsofacto.io/paths";
const SLUG = "github.com/project-slug";

const SELECTOR = /^[a-z0-9][a-z0-9._-]{0,62}$/;

export const NOT_MAPPED = "This entity is not mapped to a scope.";
export const ENV_REFUSED = "The env annotation is refused.";
export const PATHS_REFUSED = "The paths annotation is refused.";
export const REPO_REFUSED = "The repo annotation is refused.";
export const SLUG_REFUSED = "The project-slug annotation is refused.";
export const SERVICE_REFUSED = "The service annotation is refused.";
export const OUTSIDE = "The repo is outside the service.";
export const AMBIGUOUS = "The service names more than one scope.";
export const SCOPE_INCOMPLETE = "The scope list is incomplete.";
export const CATALOG_PATH = "ipso-catalog";

function unmapped() {
  return { kind: "unmapped" };
}

function error(message) {
  return { kind: "error", message };
}

function part(value) {
  return /^[a-z0-9._-]+$/.test(value);
}

function validRepo(repo) {
  if (typeof repo !== "string" || repo.length === 0 || repo.length > 140) return false;
  const slash = repo.indexOf("/");
  if (slash <= 0 || slash !== repo.lastIndexOf("/")) return false;
  const owner = repo.slice(0, slash);
  const name = repo.slice(slash + 1);
  return part(owner) && part(name);
}

function annotationsOf(entity) {
  if (!entity || typeof entity !== "object" || Array.isArray(entity)) return {};
  const metadata = entity.metadata;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return {};
  const annotations = metadata.annotations;
  if (!annotations || typeof annotations !== "object" || Array.isArray(annotations)) return {};
  return annotations;
}

function validSubjectPath(item) {
  if (item.length === 0 || item.length > 4096 || item.startsWith("/") || !item.isWellFormed()) return false;
  for (const char of item) {
    const code = char.codePointAt(0);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return false;
  }
  return item.split("/").every((segment) => segment.length > 0 && segment !== "." && segment !== "..");
}

function parsePaths(raw) {
  if (raw === undefined) return { paths: [CATALOG_PATH] };
  if (typeof raw !== "string") return error(PATHS_REFUSED);
  const paths = raw.split(",").map((item) => item.trim());
  if (paths.length === 0 || paths.length > 500 || paths.some((item) => !validSubjectPath(item))) {
    return error(PATHS_REFUSED);
  }
  return { paths };
}

function indexScopes(scopes) {
  if (!Array.isArray(scopes)) return error(SCOPE_INCOMPLETE);
  const byId = new Map();
  for (const scope of scopes) {
    if (!scope || typeof scope.id !== "string" || typeof scope.kind !== "string" || typeof scope.selector !== "string") {
      return error(SCOPE_INCOMPLETE);
    }
    if (scope.parent_id !== null && typeof scope.parent_id !== "string") return error(SCOPE_INCOMPLETE);
    if (byId.has(scope.id)) return error(SCOPE_INCOMPLETE);
    byId.set(scope.id, scope);
  }
  for (const scope of byId.values()) {
    if (scope.parent_id !== null && !byId.has(scope.parent_id)) return error(SCOPE_INCOMPLETE);
  }
  return { byId };
}

function under(scope, rootId, byId) {
  const seen = new Set();
  let current = scope;
  while (current) {
    if (seen.has(current.id)) return error(SCOPE_INCOMPLETE);
    seen.add(current.id);
    if (current.id === rootId) return { ok: true };
    if (current.parent_id === null) return { ok: false };
    current = byId.get(current.parent_id);
    if (!current) return error(SCOPE_INCOMPLETE);
  }
  return { ok: false };
}

function reposUnder(service, scopes) {
  const indexed = indexScopes(scopes);
  if (indexed.kind === "error") return indexed;
  const matches = [...indexed.byId.values()].filter((scope) => scope.kind === "service" && scope.selector === service);
  if (matches.length === 0) return unmapped();
  if (matches.length > 1) return error(AMBIGUOUS);
  const repos = [];
  for (const scope of indexed.byId.values()) {
    if (scope.kind !== "repo") continue;
    const hit = under(scope, matches[0].id, indexed.byId);
    if (hit.kind === "error") return hit;
    if (!hit.ok) continue;
    if (!validRepo(scope.selector)) return error(SCOPE_INCOMPLETE);
    repos.push(scope.selector);
  }
  return { repos: [...new Set(repos)].sort() };
}

// mapEntity reads catalog annotations. Pass scopes only after the service annotation
// has been seen, so a missing env never asks for the scope list.
export function mapEntity(entity, scopes) {
  const annotations = annotationsOf(entity);
  if (annotations[ENV] === undefined) return unmapped();
  if (typeof annotations[ENV] !== "string" || !SELECTOR.test(annotations[ENV])) return error(ENV_REFUSED);
  const paths = parsePaths(annotations[PATHS]);
  if (paths.kind === "error") return paths;

  let repo;
  if (annotations[REPO] !== undefined) {
    if (!validRepo(annotations[REPO])) return error(REPO_REFUSED);
    repo = annotations[REPO];
  } else if (annotations[SLUG] !== undefined) {
    if (!validRepo(annotations[SLUG])) return error(SLUG_REFUSED);
    repo = annotations[SLUG];
  }

  if (annotations[SERVICE] !== undefined) {
    if (typeof annotations[SERVICE] !== "string" || !SELECTOR.test(annotations[SERVICE])) return error(SERVICE_REFUSED);
    if (scopes === undefined) {
      return { kind: "needs-scopes", env: annotations[ENV], paths: paths.paths, repo, service: annotations[SERVICE] };
    }
    const placed = reposUnder(annotations[SERVICE], scopes);
    if (placed.kind === "error" || placed.kind === "unmapped") return placed;
    if (repo) {
      if (!placed.repos.includes(repo)) return error(OUTSIDE);
      return { kind: "ready", env: annotations[ENV], paths: paths.paths, repos: [repo] };
    }
    if (placed.repos.length === 0) return unmapped();
    return { kind: "ready", env: annotations[ENV], paths: paths.paths, repos: placed.repos };
  }

  if (!repo) return unmapped();
  return { kind: "ready", env: annotations[ENV], paths: paths.paths, repos: [repo] };
}
