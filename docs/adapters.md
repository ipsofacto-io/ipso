# Pulumi, CloudFormation, CDK, and Bicep

`ipso check pulumi`, `ipso check cloudformation`, and `ipso check arm` evaluate repository Rego against the output of other IaC tools, with the same modes, waivers, baselines, reports, and SARIF as `ipso check plan`. Each one reads a file the tool wrote and calls nothing: it runs no tool, resolves no parameter, and evaluates no expression.

| Tool | Write the input with | Check with | Check target |
| --- | --- | --- | --- |
| Pulumi | `pulumi preview --json > preview.json` | `ipso check pulumi preview.json` | `pulumi-preview` |
| CloudFormation | Your template, YAML or JSON | `ipso check cloudformation template.yaml` | `cloudformation-template` |
| CDK | `cdk synth`, then each `cdk.out/<stack>.template.json` | `ipso check cloudformation cdk.out/App.template.json` | `cloudformation-template` |
| Bicep | `bicep build main.bicep --outfile main.json` | `ipso check arm main.json` | `arm-template` |
| ARM | Your template | `ipso check arm azuredeploy.json` | `arm-template` |

[`ipsofacto-io/examples`](https://github.com/ipsofacto-io/examples/tree/main/adapters) runs all four real tools on every pull request, with one example that passes and one that fails for each.

## Write a decision

A check names the target and one repository Rego file. A check for one target is not evaluated for another, so a Terraform plan check never reads a CloudFormation template.

```yaml
checks:
  - engine: opa
    target: cloudformation-template
    ref: policies/no-public-buckets.rego
```

Run `ipso compile` first, as for a plan. The built-in templates of [templates.md](templates.md) target Terraform plans only, because attribute names differ between tools.

## What a policy reads

Every adapter writes the same shape, a subset of `terraform show -json`:

```json
{
  "format_version": "1.0",
  "adapter": "cloudformation",
  "resource_changes": [
    {
      "address": "LogsBucket",
      "mode": "managed",
      "type": "AWS::S3::Bucket",
      "name": "LogsBucket",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {"AccessControl": "PublicRead"},
        "after_unknown": {}
      },
      "attributes": {"DeletionPolicy": "Retain"}
    }
  ]
}
```

So a policy reads the same way for every tool:

```rego
package sample.no_public_buckets

deny contains violation if {
	some resource in input.resource_changes
	resource.type == "AWS::S3::Bucket"
	resource.change.after.AccessControl == "PublicRead"
	violation := {"msg": "S3 buckets have no public ACL", "address": resource.address}
}
```

## Pulumi

The input is the JSON that `pulumi preview --json` prints.

- `address` is the URN, `type` is the Pulumi type token, such as `aws:s3/bucket:Bucket`, and `name` is the last part of the URN.
- `after` is `newState.inputs`, and `before` is `oldState.inputs`. A step with no new state, such as a delete, has `after: null`.
- `actions` follows the step's `op`: `same` is `no-op`, `create` and `create-replacement` are `create`, `update` is `update`, `replace` is `delete` and `create`, `delete` and `delete-replaced` are `delete`, and `read` and `refresh` are `read`. An `op` ipso does not know fails the input.

Limits:

- Provider and stack steps are included. Filter on `type`.
- A value not known at preview is Pulumi's placeholder string, `after_unknown` stays empty, and a policy that compares it passes. Pulumi prints a secret as a marker object or as `[secret]`, so a policy cannot read it.
- A failed preview writes no `steps`, and that fails the input.
- Pulumi's own [CrossGuard](https://www.pulumi.com/docs/iac/crossguard/) runs earlier and sees more. This path is for decisions you want recorded and waived in ipso.

## CloudFormation and CDK

The input is one template, in YAML or JSON. `cdk synth` writes JSON, one file per stack.

- `address` and `name` are the logical id, and `type` is `Type`.
- `after` is `Properties`, `actions` is always `create`, because a template has no plan, and `before` is `null`.
- `attributes` holds every other key of the resource, such as `DeletionPolicy`, `Condition`, and `Metadata`. CDK's `aws:cdk:path` is there.
- A short intrinsic reads as its long form: `!Ref x` is `{"Ref": "x"}`, `!Sub x` is `{"Fn::Sub": "x"}`, and `!GetAtt a.b` is `{"Fn::GetAtt": ["a", "b"]}`.

Limits:

- Parameters, mappings, conditions, and intrinsics are not resolved. `AccessControl: !Ref Acl` reads as `{"Ref": "Acl"}`, so a policy comparing it to a string passes. Refuse references on the attributes that matter.
- Macros and transforms do not run, so a SAM template reads as `AWS::Serverless::Function`, and `Fn::ForEach` fails the input.
- A nested stack is one resource. Its template is not read. Check each template yourself.
- YAML anchors, aliases, merge keys, and repeated keys fail the input. CloudFormation refuses aliases too.
- CDK assets, such as Lambda code, are not read. Each stack is one run, and `--input` names it.

## Bicep and ARM

The input is one ARM template in JSON. `bicep build` writes that, so a check needs no Azure account.

- `type` is the full type, such as `Microsoft.Storage/storageAccounts`, and `name` is as written, usually an expression.
- `address` is `<type>/<name>`, or the symbolic name in a `languageVersion` 2.0 template.
- `after` is the whole resource, without its children, so a policy reads `after.properties.allowBlobPublicAccess`, `after.sku`, or `after.location`. `actions` is always `create`.
- Child resources get the parent's type and name as a prefix. The inline templates of nested deployments are walked, because a Bicep module compiles to one.

Limits:

- Parameters and expressions are not evaluated. `[parameters('tier')]` reads as that string, and a value passed into a module is not visible inside it. Refuse expressions on the attributes that matter.
- A `copy` loop is one resource, and a `condition` is not applied.
- A linked template fails the input, because its contents live at a URL. `existing` references are skipped, because they declare nothing.

## A check that selects nothing

`no checks selected` exits `0`, as it does for a plan. A misspelled target compiles and is then never evaluated. Look for the line, or check `verdicts` in the report, when you add a decision.

## Where the data goes

Plan and template data stays where the command runs. The report holds the sha256 of the input as read, and verdict counts. It does not hold addresses, values, or messages.
