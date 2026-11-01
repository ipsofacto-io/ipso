package mcptools

// Input schemas, JSON Schema 2020-12. A test requires their properties to match the input types.
const (
	applicableSchema = `{"type":"object","additionalProperties":false,"properties":{
"repo":{"type":"string","description":"The repository as owner/name. Left out, a scope that names a repository still matches."},
"paths":{"type":"array","items":{"type":"string"},"description":"Paths from the repository root that the work touches. Left out, the answer covers every path."},
"env":{"type":"string","description":"The environment the work targets. Left out, the answer covers every environment."},
"intent":{"type":"string","description":"What the work is for. It does not change the answer, because deterministic scope decides what applies."}}}`

	getSchema = `{"type":"object","additionalProperties":false,"required":["ref"],"properties":{
"ref":{"type":"string","description":"The id or slug of the decision."},
"as_of_valid":{"type":"string","description":"A YYYY-MM-DD date. in_force then answers for that date."},
"as_of_tx":{"type":"string","description":"A transaction time. Only a server with a registry can answer it."}}}`

	evaluateSchema = `{"type":"object","additionalProperties":false,"properties":{
"diff":{"type":"string","description":"A unified diff against the working tree. Give this or plan."},
"plan":{"type":"string","description":"The JSON of terraform show -json or tofu show -json. Give this or diff."},
"env":{"type":"string","description":"The environment to evaluate for."}}}`

	proposeSchema = `{"type":"object","additionalProperties":false,"required":["title","statement","rationale"],"properties":{
"title":{"type":"string","description":"A short name for the decision."},
"statement":{"type":"string","description":"What is decided."},
"rationale":{"type":"string","description":"Why, and what prompted it."},
"verification":{"type":"string","description":"How a check could prove it."},
"paths":{"type":"array","items":{"type":"string"},"description":"Globs the decision would apply to. Left out, the whole repository."},
"env":{"type":"array","items":{"type":"string"},"description":"Environments the decision would apply to."},
"session_ref":{"type":"string","description":"A reference to the agent session."}}}`
)
