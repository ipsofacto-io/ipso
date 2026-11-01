//go:build unix

package cli

import "testing"

func TestBaselineKyvernoFlow(t *testing.T) {
	root := kyvernoRepo(t, baselineNow, kyvernoCheck, false)
	writePod(t, root, "cluster-violating")
	useFakeKyverno(t, "mixed", "1")
	baselineFlow(t, root, "kyverno", 2, "k8s")
}

func TestBaselineGatekeeperFlow(t *testing.T) {
	root := gatekeeperRepo(t, baselineNow, gatekeeperCheck, false)
	writeDeployment(t, root, "gatekeeper-violating")
	useFakeGator(t, "multi", "1")
	baselineFlow(t, root, "gatekeeper", 2, "apps")
}

func TestBaselineImportlinterFlow(t *testing.T) {
	root := importlinterRepo(t, baselineNow, importlinterCheck, false)
	writeShop(t, root, "shop-violating")
	useFakeImportLinterPython(t, "shop-violating", "1")
	baselineFlow(t, root, "importlinter", 3, ".")
}

func TestBaselineESLintFlow(t *testing.T) {
	root := eslintRepo(t, baselineNow, eslintTSCheck, false, "app-violating")
	useFakeESLint(t, root, "block", "1")
	baselineFlow(t, root, "eslint", 1, "services")
}
