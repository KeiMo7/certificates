package rotation

import (
	"errors"
	"fmt"
)

// Reason classifies why a rotation operation failed. Callers can switch on the
// Reason to map it onto an HTTP/gRPC status or a readable message without
// parsing strings.
type Reason string

const (
	// ReasonConfig means a root-set configuration was rejected at load time,
	// before it could affect the running CA (e.g. overlapping windows too short,
	// no issuing root, duplicate id, illegal state regression).
	ReasonConfig Reason = "invalid_config"

	// ReasonNoIssuer means no root is currently able to issue: every root is
	// stopped, retired, or outside its validity window.
	ReasonNoIssuer Reason = "no_issuing_root"

	// ReasonNoRoot means verification found no trusted root that anchors the
	// presented chain.
	ReasonNoRoot Reason = "untrusted_root"

	// ReasonRetired means the only root that anchors the chain has been
	// retired (lifecycle StateRetired or past NotAfter).
	ReasonRetired Reason = "root_retired"

	// ReasonNotYetValid means the anchoring root's window has not started.
	ReasonNotYetValid Reason = "root_not_yet_valid"

	// ReasonBrokenChain means a chain could not be assembled because an
	// intermediate/issuer link is missing.
	ReasonBrokenChain Reason = "broken_chain"

	// ReasonReload means an online reload could not be applied; the previous
	// root set remains in force.
	ReasonReload Reason = "reload_rejected"

	// ReasonCRL means a per-root CRL could not be (re)generated; the last good
	// CRL is retained and flagged stale.
	ReasonCRL Reason = "crl_generation_failed"
)

// Error is the structured error returned by rotation operations. It carries a
// machine-readable Reason, the affected root ID when applicable, and a
// human-readable Message. MissingID is true when the failure is that a chain
// references a root the set does not contain at all.
type Error struct {
	// Reason is the stable classification.
	Reason Reason

	// RootID is the id of the root involved, empty when not applicable.
	RootID string

	// MissingID reports an issuer/root identifier that was referenced but is
	// not present in the set. It lets the caller say exactly which link is
	// missing.
	MissingID string

	// Message is the human-readable explanation.
	Message string

	// Stale, when true on a CRL error, indicates the engine kept the previous
	// usable CRL rather than serving an empty or partial one.
	Stale bool
}

func (e *Error) Error() string {
	switch {
	case e.RootID != "" && e.MissingID != "":
		return fmt.Sprintf("rotation/%s: %s (root=%s, missing=%s)", e.Reason, e.Message, e.RootID, e.MissingID)
	case e.RootID != "":
		return fmt.Sprintf("rotation/%s: %s (root=%s)", e.Reason, e.Message, e.RootID)
	case e.MissingID != "":
		return fmt.Sprintf("rotation/%s: %s (missing=%s)", e.Reason, e.Message, e.MissingID)
	default:
		return fmt.Sprintf("rotation/%s: %s", e.Reason, e.Message)
	}
}

// AsError unwraps an error to *Error.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

func newError(reason Reason, rootID, format string, args ...any) *Error {
	return &Error{Reason: reason, RootID: rootID, Message: fmt.Sprintf(format, args...)}
}

// withMissing annotates an error with the issuer/root identifier that was
// referenced but absent, so callers can name the exact missing chain link.
func (e *Error) withMissing(id []byte) *Error {
	e.MissingID = string(id)
	return e
}
