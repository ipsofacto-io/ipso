package adapter

import (
	"slices"
	"strings"
)

const armDeployments = "Microsoft.Resources/deployments"

// ARM reads an Azure Resource Manager template, which is what `bicep build` writes. Child resources
// and the inline templates of nested deployments are walked, because a Bicep module compiles to a nested
// deployment and a policy must not miss what it holds. after is the whole resource without its children.
// Template expressions stay as written, no parameter is resolved, and a copy loop is one resource.
func ARM(raw []byte) ([]byte, error) {
	var template map[string]any
	if err := parseJSON(raw, "an ARM template", &template); err != nil {
		return nil, err
	}
	if schema, ok := template["$schema"].(string); !ok || !strings.Contains(schema, "deploymentTemplate.json") {
		return nil, formatErr("expected an ARM template")
	}
	var changes []ResourceChange
	if err := walkTemplate(template, "", "", 0, &changes); err != nil {
		return nil, err
	}
	return encode("arm", changes)
}

// walkTemplate reads one template's resources. A languageVersion 2.0 template keys them by symbolic name.
func walkTemplate(template map[string]any, parentType, parentName string, depth int, out *[]ResourceChange) error {
	if depth > maxDepth {
		return formatErr("the template is too deeply nested")
	}
	switch resources := template["resources"].(type) {
	case nil:
		return nil
	case []any:
		for _, item := range resources {
			if err := walkResource(item, "", parentType, parentName, depth, out); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		names := make([]string, 0, len(resources))
		for name := range resources {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			if err := walkResource(resources[name], name, parentType, parentName, depth, out); err != nil {
				return err
			}
		}
		return nil
	default:
		return formatErr("resources is neither a list nor a mapping")
	}
}

func walkResource(item any, symbolic, parentType, parentName string, depth int, out *[]ResourceChange) error {
	resource, ok := item.(map[string]any)
	if !ok {
		return formatErr("a resource is not an object")
	}
	if existing, _ := resource["existing"].(bool); existing {
		// An existing reference declares nothing.
		return nil
	}
	kind, ok := resource["type"].(string)
	if !ok || kind == "" {
		return formatErr("a resource has no type")
	}
	name, ok := resource["name"].(string)
	if !ok || name == "" {
		return formatErr("a resource of type %q has no name", kind)
	}
	if parentType != "" {
		kind = parentType + "/" + kind
		name = parentName + "/" + name
	}
	after := make(map[string]any, len(resource))
	for key, value := range resource {
		if key != "resources" {
			after[key] = value
		}
	}
	address := kind + "/" + name
	if symbolic != "" {
		address = symbolic
	}
	*out = append(*out, ResourceChange{
		Address: address,
		Mode:    modeManaged,
		Type:    kind,
		Name:    name,
		Change:  Change{Actions: []string{actionCreate}, After: after, AfterUnknown: map[string]any{}},
	})
	if err := walkTemplate(resource, kind, name, depth+1, out); err != nil {
		return err
	}
	return walkNested(resource, kind, depth, out)
}

// walkNested reads the inline template of a nested deployment. A linked template lives at a URL, and
// that is not read, so it is refused rather than passed over.
func walkNested(resource map[string]any, kind string, depth int, out *[]ResourceChange) error {
	if !strings.EqualFold(kind, armDeployments) {
		return nil
	}
	properties, ok := resource["properties"].(map[string]any)
	if !ok {
		return nil
	}
	if _, linked := properties["templateLink"]; linked {
		return formatErr("a nested deployment links its template, and ipso renders no URL")
	}
	inline, ok := properties["template"].(map[string]any)
	if !ok {
		return nil
	}
	return walkTemplate(inline, "", "", depth+1, out)
}
