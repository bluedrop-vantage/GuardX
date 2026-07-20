package httpapi

import (
	"encoding/json"
	"net/http"
)

// GuardError is the structured error the gateway returns when a guard blocks.
type GuardError struct {
	Type      string   `json:"type"`      // "guardx.blocked" | "guardx.error"
	Message   string   `json:"message"`
	Policy    string   `json:"policy,omitempty"`
	GuardID   string   `json:"guard_id,omitempty"`
	Scenario  string   `json:"scenario,omitempty"`
	Direction string   `json:"direction,omitempty"`
	RequestID string   `json:"request_id,omitempty"`
	Reasons   []string `json:"reasons,omitempty"`
}

func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func WriteGuardBlocked(w http.ResponseWriter, ge GuardError) {
	if ge.Type == "" {
		ge.Type = "guardx.blocked"
	}
	WriteJSON(w, http.StatusForbidden, map[string]any{"error": ge})
}

func WriteInternal(w http.ResponseWriter, msg string) {
	WriteJSON(w, http.StatusInternalServerError, map[string]any{
		"error": GuardError{Type: "guardx.error", Message: msg},
	})
}
