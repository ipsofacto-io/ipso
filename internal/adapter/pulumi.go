package adapter

// pulumiActions maps the operation of a `pulumi preview --json` step to Terraform's action words.
// An operation not listed here fails the input, because a policy cannot judge a change it cannot read.
var pulumiActions = map[string][]string{
	"same":                   {"no-op"},
	"create":                 {actionCreate},
	"create-replacement":     {actionCreate},
	"import":                 {actionCreate},
	"import-replacement":     {actionCreate},
	"update":                 {"update"},
	"replace":                {"delete", actionCreate},
	"delete":                 {"delete"},
	"delete-replaced":        {"delete"},
	"read-discard":           {"delete"},
	"discard-replaced":       {"delete"},
	"remove-pending-replace": {"delete"},
	"read":                   {"read"},
	"read-replacement":       {"read"},
	"refresh":                {"read"},
}

type pulumiState struct {
	Type   string         `json:"type"`
	URN    string         `json:"urn"`
	Inputs map[string]any `json:"inputs"`
}

type pulumiStep struct {
	Op       string       `json:"op"`
	URN      string       `json:"urn"`
	NewState *pulumiState `json:"newState"`
	OldState *pulumiState `json:"oldState"`
}

// Pulumi reads the output of `pulumi preview --json`. after is the step's new inputs. Pulumi's
// placeholder for a value it does not know yet stays in place as that string.
func Pulumi(raw []byte) ([]byte, error) {
	var preview struct {
		Steps *[]pulumiStep `json:"steps"`
	}
	if err := parseJSON(raw, "the output of pulumi preview --json", &preview); err != nil {
		return nil, err
	}
	if preview.Steps == nil {
		return nil, formatErr("expected the output of pulumi preview --json")
	}
	resources := make([]ResourceChange, 0, len(*preview.Steps))
	for _, step := range *preview.Steps {
		resource, err := pulumiResource(step)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return encode("pulumi", resources)
}

func pulumiResource(step pulumiStep) (ResourceChange, error) {
	actions, ok := pulumiActions[step.Op]
	if !ok {
		return ResourceChange{}, formatErr("step has the unknown operation %q", step.Op)
	}
	state := step.NewState
	if state == nil {
		state = step.OldState
	}
	if state == nil || state.Type == "" {
		return ResourceChange{}, formatErr("step %q has no resource state", step.Op)
	}
	urn := step.URN
	if urn == "" {
		urn = state.URN
	}
	if urn == "" {
		return ResourceChange{}, formatErr("step %q has no URN", step.Op)
	}
	var before, after any
	if step.OldState != nil {
		before = step.OldState.Inputs
	}
	if step.NewState != nil {
		after = step.NewState.Inputs
	}
	return ResourceChange{
		Address: urn,
		Mode:    modeManaged,
		Type:    state.Type,
		Name:    urnName(urn),
		Change:  Change{Actions: actions, Before: before, After: after, AfterUnknown: map[string]any{}},
	}, nil
}

// urnName returns the last segment of urn:pulumi:stack::project::type::name.
func urnName(urn string) string {
	for i := len(urn) - 2; i >= 0; i-- {
		if urn[i] == ':' && urn[i+1] == ':' {
			return urn[i+2:]
		}
	}
	return urn
}
