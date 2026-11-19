# Backstage plugin

This package shows the decisions in force for one Backstage catalog entity, and how many of those decisions have passing checks. It is Apache-2.0. It does not publish itself to npm, and it does not start a Backstage app.

The Backstage backend creates the handler. `IPSO_TOKEN` is a person bearer token for the control plane, the same credential a person uses with `curl`. Set it on the backend process. Do not put it in `app-config.yaml`, because the frontend build reads that file. The package does not read a session cookie. A Backstage origin cannot send one.

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

The package name after a manual npm publish is `@ipsofacto/backstage-plugin`. This change does not publish it.

`IPSO_BASE_URL` is `https` with no userinfo, query, or fragment. The client does not follow a redirect. `renderCard` returns plain text. A Backstage card must show that text as text.

## Catalog annotations

`ipsofacto.io/env` is required. Without it the card calls no API. `ipsofacto.io/repo` is `owner/name` in lowercase. When it is absent, `github.com/project-slug` is the repo. `ipsofacto.io/service` selects every repo scope under that service. When both the service and a repo are set, the repo must sit under the service, and only that repo is read. `ipsofacto.io/paths` is a comma-separated list of relative paths. When it is absent the plugin sends `ipso-catalog`, which the control plane accepts, so a repo-level decision still matches. A path of `.`, `..`, an empty segment, or a leading slash is refused before any request.

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

The sample file in this directory is that entity.

## Coverage

The card calls `POST /v1/resolve` for each mapped repo and `GET /v1/verdicts` for each decision. A decision passes only when every repo whose resolve included it has a latest `pass` for each check in the mapped env. A verdict for another env does not count. An empty page on one repo does not pass. `fail`, `error`, `waived`, and a missing verdict do not pass. The line is `passing` of `total`. A verdict page of 100, or a card that would make a 21st call, names the decisions and does not show a percentage. Scope pages count toward those 20 calls, and the next card starts again at zero. The card shows the slug and the title. It does not show an owner, an author, or a person. Use a person token that holds only the viewer role.

`ci / backstage` runs `node --test` in this directory. A Backstage app has not loaded this package.
