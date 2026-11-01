# Kubernetes, Helm, and Kustomize

`ipso check kyverno` and `ipso check gatekeeper` read plain manifests. `ipso render` turns a Helm chart or a Kustomize directory into one, so the same compiled checks cover what those tools would deploy. Rendering needs no cluster, no kubeconfig, and no network.

```bash
ipso compile
ipso render helm charts/api --values charts/api/values-prod.yaml --out rendered/api
ipso check kyverno rendered/api
```

```bash
ipso compile
ipso render kustomize deploy/overlays/prod --out rendered/prod
ipso check gatekeeper rendered/prod
```

`ipsofacto-io/examples` runs both on every pull request, with a [sample chart and overlay](https://github.com/ipsofacto-io/examples/tree/main/kubernetes) that pass and two that fail.

## What you need on PATH

| Tool | Release | Used by |
| --- | --- | --- |
| `helm` | 4.3.1 | `ipso render helm` |
| `kustomize` | 5.8.3 | `ipso render kustomize` |
| `kyverno` | 1.19.2 | `ipso check kyverno` |
| `gator` | 3.23.1 | `ipso check gatekeeper` |

Any other release fails the command. The same chart can render differently under another Helm, and a verdict on different manifests is not the verdict you asked for.

## Verdicts

A render prints where it wrote and how many documents it holds. It has no verdict of its own: the check that reads the file reports `pass`, a violation, or `waived`, with the exit codes, report, and SARIF of any other check.

A render that fails exits `1`, and it removes the file of the previous render first, so a later check cannot pass on stale manifests. In CI, stop the job on that exit. A check named at an output directory that holds no manifest fails too.

## What a render refuses

- A chart or overlay outside the repository, and a symlink anywhere below it.
- A Kustomize entry in `resources`, `bases`, `components`, `generators`, `transformers`, or `validators` that is not a file or directory inside the repository. Remote bases and URLs fail with `render-remote`. Vendor them first, in a step you review.
- A chart whose `dependencies` are not vendored in `charts/`. Run `helm dependency build` in an earlier step.
- Kustomize exec and container plugins, and its Helm inflation. `ipso render` does not pass the flags that enable them.
- An output directory that holds any file ipso did not write.

`lookup` in a Helm template finds nothing, because there is no cluster. A chart that branches on it renders its no-cluster branch, and that is the one the check sees.

## How the tools run

The tool starts in a temporary directory with only the environment ipso gives it. Nothing else is inherited: no `KUBECONFIG`, no plugin directory, no registry login, and no secret from the job. `PATH` is empty and the proxy variables point at a closed port, so a template or a kustomization cannot fetch anything.

That is a limit on what the tools are asked to do, not an operating system sandbox. A Helm or Kustomize bug that opens its own connection or reads a file directly is not contained. Run the step in a job without production secrets.

## Keep values out of the logs

The rendered file holds whatever the values file holds, including the contents of any `Secret` the chart builds. ipso writes it at mode `0600` in a directory at mode `0700` with a `.gitignore` of `*`, and it never prints it. Two outputs can still carry a value:

- A check's violation message, if the policy quotes a field. The terminal prints it. The report and SARIF rules of each engine are unchanged.
- The first 200 bytes of a tool's error, if a template's `fail` or `required` message quotes a value.

Render with values that hold no secrets. A policy almost never needs the real password to decide whether a pod may run as root.
