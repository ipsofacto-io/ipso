package mcptools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

// LatestVersion is the protocol revision ADR-0015 targets. It has no handshake: each request
// carries its version in _meta.
const LatestVersion = "2026-07-28"

// legacyVersions start with initialize. Clients in the field still use them.
var legacyVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

const (
	metaProtocolVersion = "io.modelcontextprotocol/protocolVersion"
	metaServerInfo      = "io.modelcontextprotocol/serverInfo"

	codeParse              = -32700
	codeInvalidRequest     = -32600
	codeMethodNotFound     = -32601
	codeInvalidParams      = -32602
	codeUnsupportedVersion = -32022

	instructions = "Engineering decisions in force for this repository. Read them before editing, and propose a new decision instead of working around one. A proposal needs a person's approval."
	// toolListTTL says how long a client may cache the tool list. It changes only with a release.
	toolListTTL = 3600000
	// MaxMessageBytes bounds one JSON-RPC message. A plan or a diff travels inside one.
	MaxMessageBytes = 300 << 20
)

// Server answers MCP requests from a Backend. It holds no per-client state, so any request can
// reach any instance.
type Server struct {
	version string
	tools   []tool
}

type tool struct {
	name        string
	title       string
	description string
	readOnly    bool
	schema      string
	call        func(context.Context, json.RawMessage) (any, error)
}

// NewServer returns a server with the four tools. Only decisions.propose has a side effect, and
// that effect creates a proposal.
func NewServer(version string, backend Backend) *Server {
	return &Server{version: version, tools: []tool{
		{ToolEvaluate, "Evaluate checks", "Evaluate a unified diff or a Terraform or OpenTofu plan against the compiled checks with local engines. Returns verdicts and SARIF, and changes nothing.", true, evaluateSchema, bind(backend.Evaluate)},
		{ToolApplicable, "Applicable decisions", "List the engineering decisions in force for a repository, paths, and an environment, with their checks and state.", true, applicableSchema, bind(backend.Applicable)},
		{ToolGet, "Get a decision", "Read one engineering decision by id or slug.", true, getSchema, bind(backend.Get)},
		{ToolPropose, "Propose a decision", "Record a proposed engineering decision for a person to review. It is not in force until a person approves it.", false, proposeSchema, bind(backend.Propose)},
	}}
}

// bind decodes tool arguments strictly, so a misspelled field is an error and not an omitted one,
// which would widen an answer.
func bind[In, Out any](call func(context.Context, In) (Out, error)) func(context.Context, json.RawMessage) (any, error) {
	return func(ctx context.Context, raw json.RawMessage) (any, error) {
		var in In
		if len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&in); err != nil {
				return nil, fmt.Errorf("invalid arguments: %w", err)
			}
		}
		return call(ctx, in)
	}
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Handle answers one JSON-RPC message. A notification has no answer, and the result is nil.
func (s *Server) Handle(ctx context.Context, raw []byte) []byte {
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return encodeResponse(response{ID: json.RawMessage("null"), Error: &rpcError{Code: codeParse, Message: "parse error"}})
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		return encodeResponse(response{ID: id, Error: &rpcError{Code: codeInvalidRequest, Message: "invalid request"}})
	}
	if len(req.ID) == 0 {
		return nil
	}
	result, failure := s.dispatch(ctx, req)
	return encodeResponse(response{ID: req.ID, Result: result, Error: failure})
}

func encodeResponse(res response) []byte {
	res.JSONRPC = "2.0"
	raw, err := json.Marshal(res)
	if err != nil {
		raw, _ = json.Marshal(response{JSONRPC: "2.0", ID: res.ID, Error: &rpcError{Code: -32603, Message: "the result could not be encoded"}})
	}
	return raw
}

func (s *Server) dispatch(ctx context.Context, req request) (any, *rpcError) {
	var params struct {
		Meta            map[string]json.RawMessage `json:"_meta"`
		ProtocolVersion string                     `json:"protocolVersion"`
		Name            string                     `json:"name"`
		Arguments       json.RawMessage            `json:"arguments"`
	}
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, &rpcError{Code: codeInvalidParams, Message: "invalid params"}
		}
	}
	stateless := false
	if raw, ok := params.Meta[metaProtocolVersion]; ok {
		var version string
		if err := json.Unmarshal(raw, &version); err != nil || !slices.Contains(SupportedVersions(), version) {
			return nil, &rpcError{Code: codeUnsupportedVersion, Message: "unsupported protocol version", Data: map[string]any{"supported": SupportedVersions(), "requested": string(raw)}}
		}
		stateless = version == LatestVersion
	}

	var result map[string]any
	switch req.Method {
	case "initialize":
		return s.initialize(params.ProtocolVersion), nil
	case "ping":
		return map[string]any{}, nil
	case "server/discover":
		result = map[string]any{"supportedVersions": SupportedVersions(), "capabilities": capabilities(), "instructions": instructions, "ttlMs": toolListTTL, "cacheScope": "public"}
		stateless = true
	case "tools/list":
		result = map[string]any{"tools": s.listTools()}
		if stateless {
			result["ttlMs"] = toolListTTL
			result["cacheScope"] = "public"
		}
	case "tools/call":
		var failure *rpcError
		if result, failure = s.callTool(ctx, params.Name, params.Arguments); failure != nil {
			return nil, failure
		}
	default:
		return nil, &rpcError{Code: codeMethodNotFound, Message: "method not found"}
	}
	if stateless {
		result["resultType"] = "complete"
		result["_meta"] = map[string]any{metaServerInfo: s.serverInfo()}
	}
	return result, nil
}

// SupportedVersions lists every protocol revision the server answers, newest first.
func SupportedVersions() []string {
	return append([]string{LatestVersion}, legacyVersions...)
}

func capabilities() map[string]any {
	return map[string]any{"tools": map[string]any{}}
}

func (s *Server) serverInfo() map[string]any {
	return map[string]any{"name": "ipso", "version": s.version}
}

// initialize answers a client on an older revision. A revision the server does not know gets the
// newest one that has this handshake, and the client decides whether to continue.
func (s *Server) initialize(requested string) map[string]any {
	version := legacyVersions[0]
	if slices.Contains(legacyVersions, requested) {
		version = requested
	}
	return map[string]any{"protocolVersion": version, "capabilities": capabilities(), "serverInfo": s.serverInfo(), "instructions": instructions}
}

func (s *Server) listTools() []map[string]any {
	tools := make([]map[string]any, 0, len(s.tools))
	for _, item := range s.tools {
		tools = append(tools, map[string]any{
			"name":        item.name,
			"title":       item.title,
			"description": item.description,
			"inputSchema": json.RawMessage(item.schema),
			"annotations": map[string]any{"readOnlyHint": item.readOnly, "destructiveHint": false},
		})
	}
	return tools
}

// callTool reports a failure inside a result, so the agent can read it and correct the call. An
// unknown tool is a protocol error.
func (s *Server) callTool(ctx context.Context, name string, args json.RawMessage) (map[string]any, *rpcError) {
	index := slices.IndexFunc(s.tools, func(item tool) bool { return item.name == name })
	if index < 0 {
		return nil, &rpcError{Code: codeInvalidParams, Message: "unknown tool"}
	}
	out, err := s.tools[index].call(ctx, args)
	if err != nil {
		return map[string]any{"content": []map[string]any{{"type": "text", "text": err.Error()}}, "isError": true}, nil
	}
	text, err := json.Marshal(out)
	if err != nil {
		return map[string]any{"content": []map[string]any{{"type": "text", "text": "the result could not be encoded"}}, "isError": true}, nil
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(text)}}, "structuredContent": out, "isError": false}, nil
}

// ServeStdio answers newline-delimited messages until the input ends. Stdout is the protocol, so
// nothing else may write to out.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	reader := bufio.NewScanner(in)
	reader.Buffer(make([]byte, 64<<10), MaxMessageBytes)
	for reader.Scan() {
		line := bytes.TrimSpace(reader.Bytes())
		if len(line) == 0 {
			continue
		}
		reply := s.Handle(ctx, line)
		if reply == nil {
			continue
		}
		if _, err := out.Write(append(reply, '\n')); err != nil {
			return err
		}
	}
	if err := reader.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
