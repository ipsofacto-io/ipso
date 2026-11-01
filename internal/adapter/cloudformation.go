package adapter

import (
	"bytes"
	"errors"
	"io"
	"math"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// shortForms are the YAML tags of CloudFormation intrinsic functions. Each one reads as the long form,
// so a policy sees one shape whichever way a template is written.
var shortForms = map[string]string{
	"!Base64":       "Fn::Base64",
	"!Cidr":         "Fn::Cidr",
	"!FindInMap":    "Fn::FindInMap",
	"!GetAZs":       "Fn::GetAZs",
	"!GetAtt":       "Fn::GetAtt",
	"!ImportValue":  "Fn::ImportValue",
	"!Join":         "Fn::Join",
	"!Length":       "Fn::Length",
	"!Select":       "Fn::Select",
	"!Split":        "Fn::Split",
	"!Sub":          "Fn::Sub",
	"!ToJsonString": "Fn::ToJsonString",
	"!Transform":    "Fn::Transform",
	"!And":          "Fn::And",
	"!Equals":       "Fn::Equals",
	"!If":           "Fn::If",
	"!Not":          "Fn::Not",
	"!Or":           "Fn::Or",
	"!Ref":          "Ref",
	"!Condition":    "Condition",
}

// cloudFormationNodes bounds the walk of one template. CloudFormation itself takes at most 1 MB.
const cloudFormationNodes = 2000000

// CloudFormation reads a CloudFormation template in YAML or JSON. That is also what `cdk synth` writes.
// after is the resource's Properties. Every other key of the resource goes to attributes.
// Intrinsic functions stay as written, in their long form, and no parameter is resolved.
func CloudFormation(raw []byte) ([]byte, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return nil, formatErr("expected a CloudFormation template")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, formatErr("expected one YAML document")
	}
	count := 0
	value, err := templateValue(&root, 0, &count)
	if err != nil {
		return nil, err
	}
	template, ok := value.(map[string]any)
	if !ok {
		return nil, formatErr("expected a CloudFormation template")
	}
	resources, ok := template["Resources"].(map[string]any)
	if !ok || len(resources) == 0 {
		return nil, formatErr("the template has no Resources")
	}
	names := make([]string, 0, len(resources))
	for name := range resources {
		names = append(names, name)
	}
	slices.Sort(names)
	changes := make([]ResourceChange, 0, len(names))
	for _, name := range names {
		resource, ok := resources[name].(map[string]any)
		if !ok {
			return nil, formatErr("resource %q is not a mapping", name)
		}
		kind, ok := resource["Type"].(string)
		if !ok || kind == "" {
			return nil, formatErr("resource %q has no Type", name)
		}
		properties, hasProperties := resource["Properties"]
		if !hasProperties {
			properties = map[string]any{}
		}
		attributes := map[string]any{}
		for key, attribute := range resource {
			if key != "Type" && key != "Properties" {
				attributes[key] = attribute
			}
		}
		changes = append(changes, ResourceChange{
			Address:    name,
			Mode:       modeManaged,
			Type:       kind,
			Name:       name,
			Change:     Change{Actions: []string{actionCreate}, After: properties, AfterUnknown: map[string]any{}},
			Attributes: attributes,
		})
	}
	return encode("cloudformation", changes)
}

// templateValue turns a node into plain data. Anchors, aliases, merge keys, and duplicate keys are
// refused: CloudFormation refuses aliases too, and two readers must not see two different templates.
func templateValue(node *yaml.Node, depth int, count *int) (any, error) {
	*count++
	if depth > maxDepth || *count > cloudFormationNodes {
		return nil, formatErr("the template is too deeply nested or too large")
	}
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return nil, formatErr("the template uses a YAML anchor or alias")
	}
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) != 1 {
			return nil, formatErr("expected one YAML document")
		}
		return templateValue(node.Content[0], depth+1, count)
	case yaml.MappingNode:
		return wrapShortForm(node, mappingValue, depth, count)
	case yaml.SequenceNode:
		return wrapShortForm(node, sequenceValue, depth, count)
	case yaml.ScalarNode:
		return wrapShortForm(node, func(n *yaml.Node, _ int, _ *int) (any, error) { return scalarValue(n) }, depth, count)
	default:
		return nil, formatErr("the template holds a YAML node ipso cannot read")
	}
}

// wrapShortForm reads the node and, when it carries an intrinsic tag, wraps it in the long form.
func wrapShortForm(node *yaml.Node, read func(*yaml.Node, int, *int) (any, error), depth int, count *int) (any, error) {
	value, err := read(node, depth, count)
	if err != nil {
		return nil, err
	}
	if node.Style&yaml.TaggedStyle == 0 {
		return value, nil
	}
	long, ok := shortForms[node.Tag]
	if !ok {
		return nil, formatErr("the template uses the unknown tag %q", node.Tag)
	}
	if long == "Fn::GetAtt" {
		if text, isText := value.(string); isText {
			if resource, attribute, found := strings.Cut(text, "."); found {
				return map[string]any{long: []any{resource, attribute}}, nil
			}
		}
	}
	return map[string]any{long: value}, nil
}

func mappingValue(node *yaml.Node, depth int, count *int) (any, error) {
	out := make(map[string]any, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Kind != yaml.ScalarNode {
			return nil, formatErr("a mapping key is not a string")
		}
		if key.Value == "<<" && key.Style&yaml.TaggedStyle == 0 && key.Tag == "!!merge" {
			return nil, formatErr("the template uses a YAML merge key")
		}
		if _, dup := out[key.Value]; dup {
			return nil, formatErr("the template repeats the key %q", key.Value)
		}
		value, err := templateValue(node.Content[i+1], depth+1, count)
		if err != nil {
			return nil, err
		}
		out[key.Value] = value
	}
	return out, nil
}

func sequenceValue(node *yaml.Node, depth int, count *int) (any, error) {
	out := make([]any, 0, len(node.Content))
	for _, child := range node.Content {
		value, err := templateValue(child, depth+1, count)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

// scalarValue reads what JSON can hold. A tagged scalar is text. A date stays as written, because
// AWSTemplateFormatVersion is one, and a float JSON cannot hold stays as written too.
func scalarValue(node *yaml.Node) (any, error) {
	if node.Style&yaml.TaggedStyle != 0 {
		return node.Value, nil
	}
	switch node.ShortTag() {
	case "!!str", "!!timestamp", "!!binary":
		return node.Value, nil
	case "!!null":
		return nil, nil
	}
	var value any
	if err := node.Decode(&value); err != nil {
		return nil, formatErr("the template holds a value ipso cannot read")
	}
	if number, ok := value.(float64); ok && (math.IsNaN(number) || math.IsInf(number, 0)) {
		return node.Value, nil
	}
	return value, nil
}
