package mcptools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type fakeBackend struct{ proposed []ProposeInput }

func (f *fakeBackend) Applicable(context.Context, ApplicableInput) (ApplicableOutput, error) {
	return ApplicableOutput{Decisions: []Decision{}}, nil
}

func (f *fakeBackend) Get(context.Context, GetInput) (GetOutput, error) {
	return GetOutput{}, errors.New("no decision")
}

func (f *fakeBackend) Evaluate(context.Context, EvaluateInput) (EvaluateOutput, error) {
	return EvaluateOutput{Lines: []string{}, NotEvaluated: []string{}}, nil
}

func (f *fakeBackend) Propose(_ context.Context, in ProposeInput) (ProposeOutput, error) {
	f.proposed = append(f.proposed, in)
	return ProposeOutput{ProposalID: "p1", Status: "proposed"}, nil
}

func ask(t *testing.T, server *Server, message string) map[string]any {
	t.Helper()
	raw := server.Handle(context.Background(), []byte(message))
	if raw == nil {
		return nil
	}
	var reply map[string]any
	if err := json.Unmarshal(raw, &reply); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	return reply
}

const latestMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`

func TestLegacyClientsGetTheHandshakeAndPlainResults(t *testing.T) {
	server := NewServer("1.0.0", &fakeBackend{})
	for _, version := range legacyVersions {
		reply := ask(t, server, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+version+`","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
		result := reply["result"].(map[string]any)
		if result["protocolVersion"] != version || result["serverInfo"].(map[string]any)["name"] != "ipso" {
			t.Errorf("%s: %v", version, result)
		}
	}
	if reply := ask(t, server, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); reply != nil {
		t.Fatalf("a notification has no answer: %v", reply)
	}
	result := ask(t, server, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)["result"].(map[string]any)
	if _, ok := result["resultType"]; ok {
		t.Errorf("a legacy result has no resultType: %v", result)
	}
	if len(result["tools"].([]any)) != 4 {
		t.Errorf("tools: %v", result["tools"])
	}
	if reply := ask(t, server, `{"jsonrpc":"2.0","id":3,"method":"ping"}`); reply["error"] != nil {
		t.Errorf("ping: %v", reply)
	}
}

func TestUnknownLegacyVersionGetsTheNewestHandshake(t *testing.T) {
	result := ask(t, NewServer("1", &fakeBackend{}), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}`)["result"].(map[string]any)
	if result["protocolVersion"] != legacyVersions[0] {
		t.Fatalf("%v", result)
	}
}

func TestStatelessClients(t *testing.T) {
	server := NewServer("1.0.0", &fakeBackend{})
	discover := ask(t, server, `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+latestMeta+`}}`)["result"].(map[string]any)
	if discover["resultType"] != "complete" || discover["supportedVersions"].([]any)[0] != LatestVersion {
		t.Fatalf("discover: %v", discover)
	}
	if discover["_meta"].(map[string]any)[metaServerInfo].(map[string]any)["version"] != "1.0.0" {
		t.Fatalf("server info: %v", discover)
	}

	list := ask(t, server, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{`+latestMeta+`}}`)["result"].(map[string]any)
	if list["resultType"] != "complete" || list["ttlMs"] == nil || list["cacheScope"] != "public" {
		t.Fatalf("list: %v", list)
	}
	var names []string
	for _, item := range list["tools"].([]any) {
		names = append(names, item.(map[string]any)["name"].(string))
	}
	if !slices.IsSorted(names) {
		t.Errorf("tools must come in a fixed order: %v", names)
	}

	call := ask(t, server, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"decisions.applicable","arguments":{},`+latestMeta+`}}`)["result"].(map[string]any)
	if call["resultType"] != "complete" || call["isError"] != false || call["structuredContent"] == nil {
		t.Fatalf("call: %v", call)
	}
}

func TestUnsupportedVersionNamesWhatIsSupported(t *testing.T) {
	reply := ask(t, NewServer("1", &fakeBackend{}), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01"}}}`)
	failure := reply["error"].(map[string]any)
	if failure["code"] != float64(codeUnsupportedVersion) || !strings.Contains(string(mustJSON(t, failure["data"])), LatestVersion) {
		t.Fatalf("%v", failure)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestProtocolErrors(t *testing.T) {
	server := NewServer("1", &fakeBackend{})
	for name, tc := range map[string]struct {
		message string
		code    float64
	}{
		"not json":     {`{`, codeParse},
		"no version":   {`{"id":1,"method":"ping"}`, codeInvalidRequest},
		"no method":    {`{"jsonrpc":"2.0","id":1}`, codeInvalidRequest},
		"batch":        {`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, codeParse},
		"method":       {`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`, codeMethodNotFound},
		"tool":         {`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope"}}`, codeInvalidParams},
		"params shape": {`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[]}`, codeInvalidParams},
	} {
		t.Run(name, func(t *testing.T) {
			reply := ask(t, server, tc.message)
			if reply["error"].(map[string]any)["code"] != tc.code {
				t.Fatalf("%v", reply)
			}
		})
	}
}

func TestToolFailureIsReadableByTheAgent(t *testing.T) {
	server := NewServer("1", &fakeBackend{})
	result := ask(t, server, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"decisions.get","arguments":{"ref":"x"}}}`)["result"].(map[string]any)
	if result["isError"] != true || !strings.Contains(string(mustJSON(t, result["content"])), "no decision") {
		t.Fatalf("%v", result)
	}
}

func TestMisspelledArgumentIsRefused(t *testing.T) {
	backend := &fakeBackend{}
	result := ask(t, NewServer("1", backend), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"decisions.propose","arguments":{"title":"t","status":"accepted"}}}`)["result"].(map[string]any)
	if result["isError"] != true || len(backend.proposed) != 0 {
		t.Fatalf("%v", result)
	}
}

func TestSchemasMatchTheInputTypes(t *testing.T) {
	for _, tc := range []struct {
		schema string
		input  any
	}{
		{applicableSchema, ApplicableInput{}},
		{getSchema, GetInput{}},
		{evaluateSchema, EvaluateInput{}},
		{proposeSchema, ProposeInput{}},
	} {
		var schema struct {
			Properties map[string]any `json:"properties"`
		}
		if err := json.Unmarshal([]byte(tc.schema), &schema); err != nil {
			t.Fatal(err)
		}
		kind := reflect.TypeOf(tc.input)
		if kind.NumField() != len(schema.Properties) {
			t.Errorf("%s: %d fields, %d properties", kind.Name(), kind.NumField(), len(schema.Properties))
		}
		for i := range kind.NumField() {
			name, _, _ := strings.Cut(kind.Field(i).Tag.Get("json"), ",")
			if _, ok := schema.Properties[name]; !ok {
				t.Errorf("%s: %s is not in the schema", kind.Name(), name)
			}
		}
	}
}

func TestServeStdioAnswersEachLine(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n\n" + `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n"
	var out bytes.Buffer
	if err := NewServer("1", &fakeBackend{}).ServeStdio(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); len(lines) != 2 {
		t.Fatalf("%q", out.String())
	}
}
