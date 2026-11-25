package semgrep

import (
	"embed"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

//go:embed templates/*/*.yaml
var templateFiles embed.FS

const templateRoot = "templates"

func lookup(id string) ([]byte, bool) {
	if !compiler.ValidTemplateID(id) {
		return nil, false
	}
	data, err := templateFiles.ReadFile(templateRoot + "/" + id + ".yaml")
	if err != nil {
		return nil, false
	}
	return data, true
}

// Template is the catalog entry of one Semgrep template, read from its single rule.
type Template struct {
	ID        string
	Title     string
	Languages []string
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

// Templates lists every Semgrep template by id, with the title and languages of its rule.
func Templates() []Template {
	src := catalog()
	out := make([]Template, len(src))
	for i, entry := range src {
		out[i] = Template{ID: entry.ID, Title: entry.Title, Languages: slices.Clone(entry.Languages)}
	}
	return out
}

func readTemplate(id string, src []byte) (Template, error) {
	var file struct {
		Rules []struct {
			Languages []string `yaml:"languages"`
			Metadata  struct {
				Title string `yaml:"title"`
			} `yaml:"metadata"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(src, &file); err != nil {
		return Template{}, err
	}
	if len(file.Rules) != 1 || file.Rules[0].Metadata.Title == "" || len(file.Rules[0].Languages) == 0 {
		return Template{}, fmt.Errorf("template %s has no title or languages", id)
	}
	return Template{ID: id, Title: file.Rules[0].Metadata.Title, Languages: file.Rules[0].Languages}, nil
}

func templateIDs() []string {
	var ids []string
	err := fs.WalkDir(templateFiles, templateRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		rel := strings.TrimPrefix(path, templateRoot+"/")
		rel = strings.TrimSuffix(rel, ".yaml")
		ids = append(ids, rel)
		return nil
	})
	if err != nil {
		panic("embedded templates: " + err.Error())
	}
	sort.Strings(ids)
	return ids
}
