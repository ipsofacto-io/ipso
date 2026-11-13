package edr

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// AddCheck appends one check to the checks of an EDR file and changes nothing else. The frontmatter is
// edited through its YAML node, so key order, scalar styles and comments stay, and it is written again
// with the two-space indent of every other writer of this package. The body keeps its bytes.
//
// It returns the text unchanged and false when a check with the same ref is already there. The result must
// parse, validate, hold the original checks followed by the new one, and differ from the original in no
// other key, or AddCheck returns an error and no text. A file with mixed line endings is refused, because
// writing it back would change lines that are not the check.
func AddCheck(text string, add Check) (string, bool, error) {
	if add.Engine == "" || add.Ref == "" {
		return "", false, errors.New("a check to add names an engine and a ref")
	}
	crlf := strings.Contains(text, "\r\n")
	if crlf && strings.Count(text, "\r\n") != strings.Count(text, "\n") {
		return "", false, errors.New("the file mixes line endings")
	}
	lf := strings.ReplaceAll(text, "\r\n", "\n")
	original, err := Parse(lf)
	if err != nil {
		return "", false, err
	}
	rawFront, body, err := splitFront(lf)
	if err != nil {
		return "", false, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(rawFront), &root); err != nil {
		return "", false, fmt.Errorf("frontmatter: %w", err)
	}
	front := mappingNode(&root)
	if front == nil {
		return "", false, errors.New("frontmatter must be a mapping")
	}
	list := mappingValue(front, "checks")
	if list == nil || list.Kind != yaml.SequenceNode {
		return "", false, errors.New("checks must be a list")
	}
	existing, err := checksFrom(original.Front["checks"])
	if err != nil {
		return "", false, err
	}
	for _, check := range existing {
		if check.Ref == add.Ref {
			return text, false, nil
		}
	}

	list.Style &^= yaml.FlowStyle
	list.Content = append(list.Content, checkNode(add))

	var buf bytes.Buffer
	buf.WriteString("---\n")
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&root); err != nil {
		return "", false, fmt.Errorf("write the frontmatter: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return "", false, fmt.Errorf("write the frontmatter: %w", err)
	}
	buf.WriteString("---\n")
	buf.WriteString(body)
	out := buf.String()

	if err := sameButOneCheck(original, out, add); err != nil {
		return "", false, err
	}
	if crlf {
		out = strings.ReplaceAll(out, "\n", "\r\n")
	}
	return out, true, nil
}

func checkNode(c Check) *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	field := func(key, value string) {
		if value == "" {
			return
		}
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
	}
	field("engine", c.Engine)
	field("target", c.Target)
	field("ref", c.Ref)
	field("job", c.Job)
	field("mode", c.Mode)
	return node
}

// sameButOneCheck is the check on the rewrite: it parses and validates, its body is the original body, and
// its frontmatter is the original frontmatter with one more check.
func sameButOneCheck(original Document, out string, add Check) error {
	doc, err := Parse(out)
	if err != nil {
		return fmt.Errorf("the rewritten file does not parse: %w", err)
	}
	if problems := Validate(doc); len(problems) > 0 {
		return fmt.Errorf("the rewritten file is not valid: %s", problems[0])
	}
	if doc.Body != original.Body {
		return errors.New("the rewrite changed the body")
	}
	want := checkNode(add)
	var wantMap map[string]any
	if err := want.Decode(&wantMap); err != nil {
		return err
	}
	before, _ := original.Front["checks"].([]any)
	after, _ := doc.Front["checks"].([]any)
	if len(after) != len(before)+1 || !reflect.DeepEqual(after[:len(before)], before) {
		return errors.New("the rewrite changed the checks it keeps")
	}
	added, _ := after[len(before)].(map[string]any)
	if len(added) != len(wantMap) {
		return errors.New("the rewrite changed the check it adds")
	}
	for key, value := range wantMap {
		if added[key] != value {
			return errors.New("the rewrite changed the check it adds")
		}
	}
	rest := func(front map[string]any) map[string]any {
		out := make(map[string]any, len(front))
		for key, value := range front {
			if key != "checks" {
				out[key] = value
			}
		}
		return out
	}
	if !reflect.DeepEqual(rest(original.Front), rest(doc.Front)) {
		return errors.New("the rewrite changed a key that is not checks")
	}
	return nil
}
