package edr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Document is one EDR file split into frontmatter and body.
type Document struct {
	Front map[string]any
	Body  string
	// front is the YAML mapping, kept so an equals value can be encoded in file order.
	front *yaml.Node
}

// Slug returns the frontmatter slug, or an empty string when it is absent.
func (d Document) Slug() string {
	value, _ := d.Front["slug"].(string)
	return value
}

// Title returns the frontmatter title.
func (d Document) Title() string {
	value, _ := d.Front["title"].(string)
	return value
}

// Status returns the frontmatter status.
func (d Document) Status() string {
	value, _ := d.Front["status"].(string)
	return value
}

// ID returns the frontmatter id.
func (d Document) ID() string {
	value, _ := d.Front["id"].(string)
	return value
}

// Source is one link the frontmatter names.
type Source struct {
	Type string
	URL  string
}

// Sources returns the frontmatter sources that have a URL.
func (d Document) Sources() []Source {
	items, _ := d.Front["sources"].([]any)
	var sources []Source
	for _, item := range items {
		fields, _ := item.(map[string]any)
		url, _ := fields["url"].(string)
		if url == "" {
			continue
		}
		kind, _ := fields["type"].(string)
		sources = append(sources, Source{Type: kind, URL: url})
	}
	return sources
}

// Parse splits a Markdown file into frontmatter and body.
// Dates become YYYY-MM-DD strings so the JSON Schema can validate them.
func Parse(text string) (Document, error) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if !strings.HasPrefix(text, "---\n") {
		return Document{}, fmt.Errorf("frontmatter must start with ---")
	}
	end := strings.Index(text[4:], "\n---\n")
	if end < 0 {
		return Document{}, fmt.Errorf("frontmatter is missing the closing ---")
	}
	raw := text[4 : 4+end]
	body := text[4+end+5:]
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &root); err != nil {
		return Document{}, fmt.Errorf("frontmatter: %w", err)
	}
	frontNode := mappingNode(&root)
	if frontNode == nil {
		return Document{}, fmt.Errorf("frontmatter must be a mapping")
	}
	var front any
	if err := yaml.Unmarshal([]byte(raw), &front); err != nil {
		return Document{}, fmt.Errorf("frontmatter: %w", err)
	}
	mapping, ok := front.(map[string]any)
	if !ok {
		return Document{}, fmt.Errorf("frontmatter must be a mapping")
	}
	normalized, err := jsonRoundTrip(coerce(mapping))
	if err != nil {
		return Document{}, err
	}
	asMap, ok := normalized.(map[string]any)
	if !ok {
		return Document{}, fmt.Errorf("frontmatter must be a mapping")
	}
	return Document{Front: asMap, Body: body, front: frontNode}, nil
}

func coerce(value any) any {
	switch typed := value.(type) {
	case time.Time:
		return typed.Format("2006-01-02")
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = coerce(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = coerce(item)
		}
		return out
	default:
		return value
	}
}

func jsonRoundTrip(value any) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("frontmatter: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("frontmatter: %w", err)
	}
	return numbersToFloat(decoded), nil
}

func numbersToFloat(value any) any {
	switch typed := value.(type) {
	case json.Number:
		number, err := typed.Float64()
		if err != nil {
			return typed.String()
		}
		return number
	case map[string]any:
		for key, item := range typed {
			typed[key] = numbersToFloat(item)
		}
		return typed
	case []any:
		for i, item := range typed {
			typed[i] = numbersToFloat(item)
		}
		return typed
	default:
		return value
	}
}
