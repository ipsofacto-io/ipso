package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/compilertest"
)

func TestTemplates(t *testing.T) {
	ids := templateIDs()
	if strings.Join(ids, "\n") != strings.Join(wantTemplateIDs, "\n") {
		t.Fatalf("templates\n%s\nwant\n%s", strings.Join(ids, "\n"), strings.Join(wantTemplateIDs, "\n"))
	}
	libMod, err := parseModule(libName, libSource())
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]Template, 0, len(ids))
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			src, ok := lookup(id)
			if !ok {
				t.Fatal("missing template")
			}
			mod, err := parseModule(id+".rego", src)
			if err != nil {
				t.Fatal(err)
			}
			if mod.Package.Path.String() != packagePath(id) {
				t.Fatalf("package %s", mod.Package.Path)
			}
			if err := compileModules(map[string]*ast.Module{id + ".rego": mod, libName: libMod}); err != nil {
				t.Fatal(err)
			}
			row, err := readTemplate(id, src)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, row)
			evaluateCorpus(t, id, string(src), string(libSource()))
		})
	}
	if t.Failed() {
		return
	}
	noOrphanCorpus(t, ids)
	checkDoc(t, rows)
}

func TestSemanticCases(t *testing.T) {
	for _, path := range []string{
		"testdata/corpus/aws/ebs-encrypted/pass/delete-only.json",
		"testdata/corpus/aws/s3-kms-cmk/pass/unknown-key.json",
		"testdata/corpus/aws/s3-kms-cmk/pass/unknown-bucket-ref.json",
		"testdata/corpus/aws/s3-kms-cmk/fail/unknown-algorithm.json",
	} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("missing semantic case %s", path)
		}
	}
}

func TestTemplatesCatalog(t *testing.T) {
	got := Templates()
	if len(got) != len(wantTemplateIDs) {
		t.Fatalf("catalog has %d templates, want %d", len(got), len(wantTemplateIDs))
	}
	for i, entry := range got {
		if entry.ID != wantTemplateIDs[i] || entry.Title == "" || len(entry.Resources) == 0 {
			t.Fatalf("entry %d %#v", i, entry)
		}
	}
	got[0].Resources[0] = "changed"
	if Templates()[0].Resources[0] == "changed" {
		t.Fatal("Templates shares its slices with the caller")
	}
}

func evaluateCorpus(t *testing.T, id, policy, lib string) {
	t.Helper()
	root := filepath.Join("testdata", "corpus", filepath.FromSlash(id))
	pass := readPlans(t, filepath.Join(root, "pass"))
	fail := readPlans(t, filepath.Join(root, "fail"))
	if len(pass) == 0 || len(fail) == 0 {
		t.Fatalf("corpus pass %d fail %d", len(pass), len(fail))
	}
	for name, plan := range pass {
		got := denials(t, packagePath(id), policy, lib, plan)
		if len(got) != 0 {
			t.Errorf("pass %s denied %v", name, got)
		}
		if eval := evalDenials(t, policy, lib, plan); !sameDenials(got, eval) {
			t.Errorf("pass %s evaluator %v direct %v", name, eval, got)
		}
	}
	for name, plan := range fail {
		got := denials(t, packagePath(id), policy, lib, plan)
		want := readWant(t, filepath.Join(root, "fail", strings.TrimSuffix(name, ".json")+".want"))
		if strings.Join(sortedKeys(got), "\n") != strings.Join(want, "\n") {
			t.Errorf("fail %s addresses %v want %v messages %#v", name, sortedKeys(got), want, got)
		}
		if eval := evalDenials(t, policy, lib, plan); !sameDenials(got, eval) {
			t.Errorf("fail %s evaluator %v direct %v", name, eval, got)
		}
		for addr, msgs := range got {
			for _, msg := range msgs {
				if msg == "" {
					t.Errorf("%s %s empty message", name, addr)
				}
				if strings.Contains(name, "unknown") && !strings.Contains(msg, "unknown") {
					t.Errorf("%s %s message %q", name, addr, msg)
				}
			}
		}
	}
}

func readPlans(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[entry.Name()] = body
	}
	return out
}

func readWant(t *testing.T, path string) []string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	sort.Strings(lines)
	return lines
}

func evalDenials(t *testing.T, policy, lib string, plan []byte) map[string][]string {
	t.Helper()
	value, err := planValue(plan)
	if err != nil {
		t.Fatal(err)
	}
	parsed := Plan{raw: plan, value: value}
	outcome := EvalCheck(compiler.Entry{}, map[string][]byte{
		"policy.rego":    []byte(policy),
		"terraform.rego": []byte(lib),
	}, parsed, time.Now())
	if outcome.Err != nil {
		t.Fatal(outcome.Err)
	}
	out := map[string][]string{}
	for _, violation := range outcome.Violations {
		out[violation.Address] = append(out[violation.Address], violation.Message)
	}
	return out
}

func sameDenials(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for addr, msgs := range left {
		if strings.Join(msgs, "\n") != strings.Join(right[addr], "\n") {
			return false
		}
	}
	return true
}

func denials(t *testing.T, pkg, policy, lib string, plan []byte) map[string][]string {
	t.Helper()
	var input any
	if err := json.Unmarshal(plan, &input); err != nil {
		t.Fatal(err)
	}
	rs, err := rego.New(
		rego.Query(pkg+".deny"),
		rego.Module("policy.rego", policy),
		rego.Module(libName, lib),
		rego.Input(input),
		rego.SetRegoVersion(ast.RegoV1),
	).Eval(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return map[string][]string{}
	}
	return denialSet(t, rs[0].Expressions[0].Value)
}

func denialSet(t *testing.T, value any) map[string][]string {
	t.Helper()
	if value == nil {
		return map[string][]string{}
	}
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("deny value %T %#v", value, value)
	}
	out := map[string][]string{}
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("denial %T", item)
		}
		addr, _ := obj["address"].(string)
		msg, _ := obj["msg"].(string)
		if addr == "" || msg == "" {
			t.Fatalf("denial %#v", obj)
		}
		out[addr] = append(out[addr], msg)
	}
	return out
}

func sortedKeys(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func noOrphanCorpus(t *testing.T, ids []string) {
	t.Helper()
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	root := filepath.Join("testdata", "corpus")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) != 4 || (parts[2] != "pass" && parts[2] != "fail") {
			t.Errorf("unexpected corpus path %s", rel)
			return nil
		}
		id := parts[0] + "/" + parts[1]
		if !known[id] {
			t.Errorf("orphan corpus %s", id)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func checkDoc(t *testing.T, rows []Template) {
	t.Helper()
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	got := renderDoc(rows)
	path := filepath.Join("..", "..", "..", "docs", "templates.md")
	if compilertest.Updating() {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read docs/templates.md: %v (go test ./internal/compiler/opa -update)", err)
	}
	if string(body) != got {
		t.Fatalf("docs/templates.md drifted\n%s", got)
	}
}

func renderDoc(rows []Template) string {
	var b strings.Builder
	b.WriteString("# Terraform plan templates\n\n")
	b.WriteString("A check with `engine: opa` and `ref: ipso:<id>` compiles one of these templates. The check `target` must be `terraform-plan`. Each template reads a Terraform or OpenTofu plan and denies with an object that carries `msg` and `address`.\n\n")
	b.WriteString("Schemas are hashicorp/aws 6.x and hashicorp/azurerm 5.x.\n\n")
	b.WriteString("| id | title | resources |\n")
	b.WriteString("| --- | --- | --- |\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", row.ID, row.Title, strings.Join(row.Resources, ", "))
	}
	return b.String()
}

var wantTemplateIDs = []string{
	"aws/ebs-encrypted",
	"aws/ec2-imdsv2-required",
	"aws/kms-key-rotation",
	"aws/lb-http-redirects-to-https",
	"aws/rds-not-public",
	"aws/rds-storage-encrypted",
	"aws/s3-kms-cmk",
	"aws/s3-no-public-acl",
	"aws/s3-public-access-block",
	"aws/sg-no-rdp-from-internet",
	"aws/sg-no-ssh-from-internet",
	"azure/aks-private-cluster",
	"azure/keyvault-purge-protection",
	"azure/nsg-no-rdp-from-internet",
	"azure/nsg-no-ssh-from-internet",
	"azure/sql-no-public-network",
	"azure/storage-https-only",
	"azure/storage-min-tls-1-2",
	"azure/storage-no-public-blob",
	"terraform/postgres-only",
}

func TestLibIsNotATemplate(t *testing.T) {
	if _, ok := lookup("lib/terraform"); ok {
		t.Fatal("lib/terraform is a template")
	}
}
