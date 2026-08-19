package protocol

// AllowedTransitions is the canonical, versioned lifecycle state machine. It is
// the single source of truth for which edits are legal, so the control plane,
// provider adapters, and conformance tests all reason about the same rules.
var AllowedTransitions = map[State]map[State]bool{
	StateRegistered: {
		StateActive: true,
	},
	StateActive: {
		StateRenewing: true,
		StateRetired:  true,
	},
	StateRenewing: {
		StateActive:  true,
		StateRetired: true, // aborted renewal may retire
	},
	StateRetired: {},
}

// CanTransition reports whether the state machine permits from -> to. It never
// panics and treats unknown states as invalid.
func CanTransition(from, to State) bool {
	toMap, ok := AllowedTransitions[from]
	if !ok {
		return false
	}
	return toMap[to]
}

// KnownStates lists all canonical states in declaration order.
func KnownStates() []State {
	return []State{StateRegistered, StateActive, StateRenewing, StateRetired}
}
