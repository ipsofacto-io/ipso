package opa

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

//go:embed templates
var templateFiles embed.FS

const templateRoot = "templates"

func libSource() []byte {
	data, err := templateFiles.ReadFile(templateRoot + "/lib/terraform.rego")
	if err != nil {
		panic("embedded terraform.rego: " + err.Error())
	}
	return data
}

func lookup(id string) ([]byte, bool) {
	provider, _, _ := strings.Cut(id, "/")
	// lib holds the helper module, which is not a decision template.
	if provider == "lib" || !compiler.ValidTemplateID(id) {
		return nil, false
	}
	data, err := templateFiles.ReadFile(templateRoot + "/" + id + ".rego")
	if err != nil {
		return nil, false
	}
	return data, true
}

func templateIDs() []string {
	var ids []string
	err := fs.WalkDir(templateFiles, templateRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}
		rel := strings.TrimPrefix(path, templateRoot+"/")
		rel = strings.TrimSuffix(rel, ".rego")
		if strings.HasPrefix(rel, "lib/") {
			return nil
		}
		ids = append(ids, rel)
		return nil
	})
	if err != nil {
		panic("embedded templates: " + err.Error())
	}
	sort.Strings(ids)
	return ids
}

// Template is the catalog entry of one plan template, read from the METADATA block of its module.
type Template struct {
	ID        string
	Title     string
	Resources []string
}

var catalog = sync.OnceValue(func() []Template {
	ids := templateIDs()
	out := make([]Template, 0, len(ids))
	for _, id := range ids {
		src, _ := lookup(id)
		entry, err := readTemplate(id, src)
		if err != nil {
			panic("embedded template " + id + ": " + err.Error())
		}
		out = append(out, entry)
	}
	return out
})

// Templates lists every plan template by id, with the title and resources of its METADATA block.
func Templates() []Template {
	src := catalog()
	out := make([]Template, len(src))
	for i, entry := range src {
		out[i] = Template{ID: entry.ID, Title: entry.Title, Resources: slices.Clone(entry.Resources)}
	}
	return out
}

func readTemplate(id string, src []byte) (Template, error) {
	mod, err := parseModule(id+".rego", src)
	if err != nil {
		return Template{}, err
	}
	if len(mod.Annotations) == 0 {
		return Template{}, errors.New("missing metadata")
	}
	ann := mod.Annotations[0]
	provider, _ := ann.Custom["provider"].(string)
	resources := stringList(ann.Custom["resources"])
	if ann.Title == "" || ann.Description == "" || provider == "" || len(resources) == 0 {
		return Template{}, fmt.Errorf("metadata title %q description %q provider %q resources %#v", ann.Title, ann.Description, provider, ann.Custom["resources"])
	}
	if want, _, _ := strings.Cut(id, "/"); provider != want {
		return Template{}, fmt.Errorf("provider %s", provider)
	}
	return Template{ID: id, Title: ann.Title, Resources: resources}, nil
}

func stringList(value any) []string {
	switch items := value.(type) {
	case []any:
		out := make([]string, 0, len(items))
		for _, item := range items {
			text, ok := item.(string)
			if !ok {
				return nil
			}
			out = append(out, text)
		}
		return out
	case []string:
		return append([]string(nil), items...)
	default:
		return nil
	}
}

func packagePath(id string) string {
	dotted := strings.ReplaceAll(strings.ReplaceAll(id, "-", "_"), "/", ".")
	return "data.ipso.templates." + dotted
}
