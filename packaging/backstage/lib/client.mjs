import { PAGE_LIMIT } from "./coverage.mjs";

const REFUSED = { code: "refused" };
const INCOMPLETE = { code: "incomplete" };
const BUDGET = { code: "budget" };
export const CALL_BUDGET = 20;

function refused() {
  return Object.assign(new Error("request refused"), REFUSED);
}

function incomplete() {
  return Object.assign(new Error("scope list is incomplete"), INCOMPLETE);
}

export function checkBase(raw) {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 2048) throw refused();
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw refused();
  }
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/") throw refused();
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1";
  if (url.protocol === "https:") return url;
  if (url.protocol === "http:" && loopback) return url;
  throw refused();
}

function safeToken(token) {
  if (typeof token !== "string" || token.length < 20 || token.length > 8192) return false;
  for (const char of token) {
    if (char < "!" || char > "~" || char === '"' || char === "\\") return false;
  }
  return true;
}

export function createClient({ baseUrl, token, fetch: fetchImpl }) {
  const base = checkBase(baseUrl);
  if (!safeToken(token)) throw refused();
  if (typeof fetchImpl !== "function") throw refused();
  if (base.href.includes(token)) throw refused();

  function open() {
    let used = 0;
    async function call(method, path, body) {
      if (used >= CALL_BUDGET) throw Object.assign(new Error("call budget"), BUDGET);
      used += 1;
      const target = new URL(path, base);
      if (target.origin !== base.origin || !target.pathname.startsWith("/v1/")) throw refused();
      const headers = { accept: "application/json", authorization: `Bearer ${token}` };
      const init = { method, headers, redirect: "error" };
      if (body !== undefined) {
        headers["content-type"] = "application/json";
        init.body = JSON.stringify(body);
      }
      let response;
      try {
        response = await fetchImpl(target, init);
      } catch {
        throw refused();
      }
      if (!response || response.ok !== true) throw refused();
      try {
        return await response.json();
      } catch {
        throw refused();
      }
    }

    return {
      async scopes() {
        const all = [];
        let before = "";
        for (let page = 0; page < 20; page += 1) {
          const params = new URLSearchParams({ limit: String(PAGE_LIMIT) });
          if (before) params.set("before", before);
          const body = await call("GET", `/v1/scopes?${params}`);
          if (!body || !Array.isArray(body.scopes)) throw refused();
          all.push(...body.scopes);
          if (body.scopes.length < PAGE_LIMIT) return all;
          const last = body.scopes[body.scopes.length - 1];
          if (!last || typeof last.id !== "string" || last.id.length === 0) throw refused();
          before = last.id;
        }
        throw incomplete();
      },
      resolve(repo, env, paths) {
        return call("POST", "/v1/resolve", { repo, env, paths });
      },
      verdicts(repo, decision) {
        const params = new URLSearchParams({ repo, decision, limit: String(PAGE_LIMIT) });
        return call("GET", `/v1/verdicts?${params}`);
      },
    };
  }

  return { open };
}
