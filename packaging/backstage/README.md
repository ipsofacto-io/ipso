# Backstage plugin

Backstage plugin package (`@ipsofacto/backstage-plugin`, Apache-2.0) that displays the ipso decisions in force for a catalog entity and how many of them have passing checks.

> Status: `ci / backstage` runs `node --test` against the handler and card renderer. npm publishing is manual, and this package has not yet been loaded inside a running Backstage app.

## Backend setup

Create the handler in your Backstage backend using a read-only (`viewer` role) person bearer token in `IPSO_TOKEN`. Keep `IPSO_TOKEN` in the backend process environment, never in `app-config.yaml` (which is exposed to the frontend build).

```javascript
import { createHandler, renderCard } from "./lib/handler.mjs";

const handle = createHandler({
  baseUrl: process.env.IPSO_BASE_URL,
  token: process.env.IPSO_TOKEN,
  fetch,
});

const view = await handle(entity);
const text = renderCard(view);
```

- `IPSO_BASE_URL` must be an `https` URL with no userinfo, query, or fragment.
- The client refuses HTTP redirects and never reads browser session cookies.
- `renderCard` returns plain text; render it as plain text in your Backstage card.

## Catalog annotations

See [`catalog-info.yaml`](catalog-info.yaml) in this directory for a complete example:

```yaml
apiVersion: backstage.io/v1alpha1
kind: Component
metadata:
  name: payments
  annotations:
    ipsofacto.io/repo: acme/payments
    ipsofacto.io/env: prod
    github.com/project-slug: acme/payments
spec:
  type: service
```

| Annotation | Required | Behavior |
| --- | --- | --- |
| `ipsofacto.io/env` | Yes | Target environment; without it the card makes no API calls |
| `ipsofacto.io/repo` | No | Lowercase `owner/name`; falls back to `github.com/project-slug` when omitted |
| `ipsofacto.io/service` | No | Resolves all repo scopes under that service; if paired with `ipsofacto.io/repo`, verifies the repo belongs to the service and checks only that repo |
| `ipsofacto.io/paths` | No | Comma-separated relative paths (defaults to `ipso-catalog` so repo-level decisions still match); `.`, `..`, empty segments, and leading slashes are rejected before any request |

## Coverage calculation

- Calls `POST /v1/resolve` per mapped repo and `GET /v1/verdicts` per decision.
- A decision counts as passing only when every repo that resolved it has a latest `pass` verdict for every check in the mapped environment (`fail`, `error`, `waived`, other environments, and empty verdict pages do not pass).
- Displays `passing` of `total` along with each decision's slug and title (never owners, authors, or people).
- If a verdict page hits 100 items or a card hits its 20-request call budget (including scope pagination), the card lists the decisions without showing a percentage.
