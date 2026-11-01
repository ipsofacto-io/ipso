package adapter

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

func decode(t *testing.T, raw []byte) Document {
	t.Helper()
	var document Document
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func wantFormatError(t *testing.T, err error) {
	t.Helper()
	var coded *compiler.Error
	if !errors.As(err, &coded) || coded.Code != CodeFormat {
		t.Fatalf("err %v, want code %s", err, CodeFormat)
	}
}

func TestReadCap(t *testing.T) {
	raw, err := Read(strings.NewReader("{}"))
	if err != nil || string(raw) != "{}" {
		t.Fatalf("raw %q err %v", raw, err)
	}
}

const pulumiPreview = `{
  "steps": [
    {"op": "create", "urn": "urn:pulumi:dev::app::pulumi:pulumi:Stack::app-dev", "newState": {"type": "pulumi:pulumi:Stack", "urn": "urn:pulumi:dev::app::pulumi:pulumi:Stack::app-dev"}},
    {"op": "create", "urn": "urn:pulumi:dev::app::random:index/randomPassword:RandomPassword::db", "newState": {"type": "random:index/randomPassword:RandomPassword", "inputs": {"length": 8}}},
    {"op": "update", "urn": "urn:pulumi:dev::app::aws:s3/bucket:Bucket::logs", "oldState": {"type": "aws:s3/bucket:Bucket", "inputs": {"acl": "private"}}, "newState": {"type": "aws:s3/bucket:Bucket", "inputs": {"acl": "public-read"}}},
    {"op": "delete", "urn": "urn:pulumi:dev::app::aws:s3/bucket:Bucket::old", "oldState": {"type": "aws:s3/bucket:Bucket", "inputs": {"acl": "private"}}}
  ],
  "changeSummary": {"create": 2}
}`

func TestPulumi(t *testing.T) {
	raw, err := Pulumi([]byte(pulumiPreview))
	if err != nil {
		t.Fatal(err)
	}
	document := decode(t, raw)
	if document.Adapter != "pulumi" || document.FormatVersion != "1.0" || len(document.ResourceChanges) != 4 {
		t.Fatalf("document %+v", document)
	}
	password := document.ResourceChanges[1]
	if password.Type != "random:index/randomPassword:RandomPassword" || password.Name != "db" || password.Address != "urn:pulumi:dev::app::random:index/randomPassword:RandomPassword::db" {
		t.Fatalf("password %+v", password)
	}
	if password.Change.Actions[0] != "create" || password.Change.After.(map[string]any)["length"] != float64(8) {
		t.Fatalf("change %+v", password.Change)
	}
	bucket := document.ResourceChanges[2]
	if bucket.Change.Before.(map[string]any)["acl"] != "private" || bucket.Change.After.(map[string]any)["acl"] != "public-read" {
		t.Fatalf("bucket %+v", bucket)
	}
	deleted := document.ResourceChanges[3]
	if deleted.Change.Actions[0] != "delete" || deleted.Change.After != nil || deleted.Type != "aws:s3/bucket:Bucket" {
		t.Fatalf("deleted %+v", deleted)
	}
}

func TestPulumiEmptyPreviewIsNotAnError(t *testing.T) {
	raw, err := Pulumi([]byte(`{"steps": []}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(decode(t, raw).ResourceChanges) != 0 {
		t.Fatalf("raw %s", raw)
	}
}

func TestPulumiFormat(t *testing.T) {
	for name, input := range map[string]string{
		"not JSON":     "preview failed",
		"no steps":     `{"diagnostics": []}`,
		"steps null":   `{"steps": null}`,
		"unknown op":   `{"steps": [{"op": "teleport", "urn": "u", "newState": {"type": "t"}}]}`,
		"no state":     `{"steps": [{"op": "create", "urn": "u"}]}`,
		"no type":      `{"steps": [{"op": "create", "urn": "u", "newState": {}}]}`,
		"no urn":       `{"steps": [{"op": "create", "newState": {"type": "t"}}]}`,
		"a plain list": `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Pulumi([]byte(input))
			wantFormatError(t, err)
		})
	}
}

const cfnYAML = `AWSTemplateFormatVersion: 2010-09-09
Parameters:
  Name:
    Type: String
Conditions:
  IsProd: !Equals [!Ref Name, prod]
Resources:
  Zeta:
    Type: AWS::SNS::Topic
  Logs:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    Condition: IsProd
    Properties:
      BucketName: !Sub "${Name}-logs"
      AccessControl: PublicRead
      Count: 3
      Enabled: true
      Nothing: null
      Arn: !GetAtt Zeta.TopicArn
      Tags:
        - Key: owner
          Value: !Join ["-", [a, !Ref Name]]
`

func TestCloudFormationYAML(t *testing.T) {
	raw, err := CloudFormation([]byte(cfnYAML))
	if err != nil {
		t.Fatal(err)
	}
	document := decode(t, raw)
	if document.Adapter != "cloudformation" || len(document.ResourceChanges) != 2 {
		t.Fatalf("document %+v", document)
	}
	logs := document.ResourceChanges[0]
	if logs.Address != "Logs" || logs.Type != "AWS::S3::Bucket" || logs.Change.Actions[0] != "create" {
		t.Fatalf("logs %+v", logs)
	}
	if logs.Attributes["DeletionPolicy"] != "Retain" || logs.Attributes["Condition"] != "IsProd" {
		t.Fatalf("attributes %+v", logs.Attributes)
	}
	after := logs.Change.After.(map[string]any)
	if after["AccessControl"] != "PublicRead" || after["Count"] != float64(3) || after["Enabled"] != true {
		t.Fatalf("after %+v", after)
	}
	if after["BucketName"].(map[string]any)["Fn::Sub"] != "${Name}-logs" {
		t.Fatalf("sub %+v", after["BucketName"])
	}
	getAtt := after["Arn"].(map[string]any)["Fn::GetAtt"].([]any)
	if getAtt[0] != "Zeta" || getAtt[1] != "TopicArn" {
		t.Fatalf("getatt %+v", getAtt)
	}
	join := after["Tags"].([]any)[0].(map[string]any)["Value"].(map[string]any)["Fn::Join"].([]any)
	if join[0] != "-" || join[1].([]any)[1].(map[string]any)["Ref"] != "Name" {
		t.Fatalf("join %+v", join)
	}
	if topic := document.ResourceChanges[1]; topic.Address != "Zeta" || len(topic.Change.After.(map[string]any)) != 0 {
		t.Fatalf("topic %+v", topic)
	}
}

func TestCloudFormationJSONAsCDKWritesIt(t *testing.T) {
	const synth = `{"Resources":{"LogsBucketABC123":{"Type":"AWS::S3::Bucket","Properties":{"PublicAccessBlockConfiguration":{"BlockPublicAcls":false}},"UpdateReplacePolicy":"Retain","Metadata":{"aws:cdk:path":"AppStack/Logs/Resource"}}},"Parameters":{"BootstrapVersion":{"Type":"AWS::SSM::Parameter::Value<String>","Default":"/cdk-bootstrap/hnb659fds/version"}}}`
	raw, err := CloudFormation([]byte(synth))
	if err != nil {
		t.Fatal(err)
	}
	resource := decode(t, raw).ResourceChanges[0]
	if resource.Address != "LogsBucketABC123" || resource.Attributes["Metadata"].(map[string]any)["aws:cdk:path"] != "AppStack/Logs/Resource" {
		t.Fatalf("resource %+v", resource)
	}
	access := resource.Change.After.(map[string]any)["PublicAccessBlockConfiguration"].(map[string]any)
	if access["BlockPublicAcls"] != false {
		t.Fatalf("after %+v", resource.Change.After)
	}
}

func TestCloudFormationFormat(t *testing.T) {
	for name, input := range map[string]string{
		"not YAML":          "a: [",
		"not a mapping":     "- a\n- b\n",
		"no resources":      "Parameters: {}\n",
		"empty resources":   "Resources: {}\n",
		"two documents":     "Resources:\n  A:\n    Type: T\n---\nResources:\n  B:\n    Type: T\n",
		"resource a string": "Resources:\n  A: text\n",
		"no type":           "Resources:\n  A:\n    Properties: {}\n",
		"type not text":     "Resources:\n  A:\n    Type: [T]\n",
		"an alias":          "Resources:\n  A: &a\n    Type: T\n  B: *a\n",
		"a merge key":       "x: &base\n  Type: T\nResources:\n  A:\n    <<: *base\n",
		"a duplicate key":   "Resources:\n  A:\n    Type: T\n  A:\n    Type: U\n",
		"an unknown tag":    "Resources:\n  A:\n    Type: !Nope T\n",
		"a language loop":   "Resources:\n  Fn::ForEach::Topics:\n    - Name\n    - [a]\n    - T: {Type: T}\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := CloudFormation([]byte(input))
			wantFormatError(t, err)
		})
	}
}

func TestCloudFormationDepth(t *testing.T) {
	nested := strings.Repeat("[", maxDepth+5) + strings.Repeat("]", maxDepth+5)
	_, err := CloudFormation([]byte("Resources:\n  A:\n    Type: T\n    Properties: " + nested + "\n"))
	wantFormatError(t, err)
}

const armSchema = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"

func TestARMAsBicepWritesIt(t *testing.T) {
	template := `{
  "$schema": "` + armSchema + `",
  "contentVersion": "1.0.0.0",
  "parameters": {"name": {"type": "string"}},
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-05-01",
      "name": "[parameters('name')]",
      "location": "westeurope",
      "properties": {"allowBlobPublicAccess": true},
      "resources": [
        {"type": "blobServices", "apiVersion": "2023-05-01", "name": "default", "properties": {}}
      ]
    },
    {
      "type": "Microsoft.Resources/deployments",
      "apiVersion": "2022-09-01",
      "name": "network",
      "properties": {
        "mode": "Incremental",
        "template": {
          "$schema": "` + armSchema + `",
          "resources": [
            {"type": "Microsoft.Network/publicIPAddresses", "apiVersion": "2023-05-01", "name": "edge", "properties": {}}
          ]
        }
      }
    }
  ]
}`
	raw, err := ARM([]byte(template))
	if err != nil {
		t.Fatal(err)
	}
	document := decode(t, raw)
	if document.Adapter != "arm" || len(document.ResourceChanges) != 4 {
		t.Fatalf("document %+v", document)
	}
	account := document.ResourceChanges[0]
	if account.Type != "Microsoft.Storage/storageAccounts" || account.Name != "[parameters('name')]" {
		t.Fatalf("account %+v", account)
	}
	after := account.Change.After.(map[string]any)
	if after["properties"].(map[string]any)["allowBlobPublicAccess"] != true || after["resources"] != nil || after["location"] != "westeurope" {
		t.Fatalf("after %+v", after)
	}
	child := document.ResourceChanges[1]
	if child.Type != "Microsoft.Storage/storageAccounts/blobServices" || child.Name != "[parameters('name')]/default" {
		t.Fatalf("child %+v", child)
	}
	if nested := document.ResourceChanges[3]; nested.Type != "Microsoft.Network/publicIPAddresses" || nested.Address != "Microsoft.Network/publicIPAddresses/edge" {
		t.Fatalf("nested %+v", nested)
	}
}

func TestARMSymbolicNames(t *testing.T) {
	template := `{
  "$schema": "` + armSchema + `",
  "languageVersion": "2.0",
  "resources": {
    "zeta": {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-05-01", "name": "z", "properties": {}},
    "alpha": {"type": "Microsoft.Web/sites", "apiVersion": "2023-05-01", "name": "a", "properties": {}},
    "other": {"existing": true, "type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01", "name": "shared"}
  }
}`
	raw, err := ARM([]byte(template))
	if err != nil {
		t.Fatal(err)
	}
	changes := decode(t, raw).ResourceChanges
	if len(changes) != 2 || changes[0].Address != "alpha" || changes[1].Address != "zeta" {
		t.Fatalf("changes %+v", changes)
	}
}

func TestARMFormat(t *testing.T) {
	for name, input := range map[string]string{
		"not JSON":        "resources:",
		"no schema":       `{"resources": []}`,
		"another schema":  `{"$schema": "https://example.test/x.json", "resources": []}`,
		"resources text":  `{"$schema": "` + armSchema + `", "resources": "x"}`,
		"resource text":   `{"$schema": "` + armSchema + `", "resources": ["x"]}`,
		"no type":         `{"$schema": "` + armSchema + `", "resources": [{"name": "a"}]}`,
		"no name":         `{"$schema": "` + armSchema + `", "resources": [{"type": "a"}]}`,
		"linked template": `{"$schema": "` + armSchema + `", "resources": [{"type": "Microsoft.Resources/deployments", "name": "n", "properties": {"templateLink": {"uri": "https://example.test/t.json"}}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ARM([]byte(input))
			wantFormatError(t, err)
		})
	}
}

func TestARMDepth(t *testing.T) {
	inner := `{"type":"Microsoft.Resources/deployments","name":"n","properties":{"template":{"resources":[%s]}}}`
	nested := `{"type":"t","name":"n"}`
	for range maxDepth + 2 {
		nested = strings.Replace(inner, "%s", nested, 1)
	}
	_, err := ARM([]byte(`{"$schema": "` + armSchema + `", "resources": [` + nested + `]}`))
	wantFormatError(t, err)
}
