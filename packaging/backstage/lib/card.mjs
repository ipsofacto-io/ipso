import { NOT_MAPPED } from "./map.mjs";

export const INCOMPLETE = "Verdict list incomplete.";
export const REFUSED = "The control plane refused the request.";

function line(decision) {
  const name = decision.slug || decision.id;
  return decision.title ? `${name} ${decision.title}` : name;
}

export function renderCard(view) {
  if (!view || view.state === "unmapped") return NOT_MAPPED;
  if (view.state === "error") return view.message;
  const lines = Array.isArray(view.decisions) ? view.decisions.map(line) : [];
  if (view.state === "incomplete") return [INCOMPLETE, ...lines].join("\n");
  return [`${view.passing} of ${view.total} decisions passing`, ...lines].join("\n");
}
