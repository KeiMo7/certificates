package api

import (
	"context"
	"net/http"

	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/errs"
)

type batchRevocationAuthority interface {
	PreviewRevokeBatch(context.Context, *authority.RevokeBatchOptions) (*authority.RevokeBatchPreview, error)
	RevokeBatch(context.Context, *authority.RevokeBatchOptions) (*authority.RevokeBatchResult, error)
}

// RevokeBatchRequest is the body for previewing or committing a batch
// revocation.
type RevokeBatchRequest struct {
	Serials      []string `json:"serials"`
	Reason       string   `json:"reason"`
	ReasonCode   int      `json:"reasonCode"`
	Confirmation string   `json:"confirmation,omitempty"`
}

func (r *RevokeBatchRequest) options() *authority.RevokeBatchOptions {
	return &authority.RevokeBatchOptions{
		Serials:      r.Serials,
		Reason:       r.Reason,
		ReasonCode:   r.ReasonCode,
		Confirmation: r.Confirmation,
	}
}

// PreviewRevokeBatch returns the certificates affected by a proposed batch.
func PreviewRevokeBatch(w http.ResponseWriter, r *http.Request) {
	var body RevokeBatchRequest
	if err := read.JSON(r.Body, &body); err != nil {
		render.Error(w, r, errs.BadRequestErr(err, "error reading request body"))
		return
	}

	auth, ok := mustAuthority(r.Context()).(batchRevocationAuthority)
	if !ok {
		render.Error(w, r, errs.NotImplemented("batch revocation is not supported"))
		return
	}
	preview, err := auth.PreviewRevokeBatch(r.Context(), body.options())
	if err != nil {
		render.Error(w, r, err)
		return
	}
	render.JSON(w, r, preview)
}

// RevokeBatch commits a previously previewed batch revocation.
func RevokeBatch(w http.ResponseWriter, r *http.Request) {
	var body RevokeBatchRequest
	if err := read.JSON(r.Body, &body); err != nil {
		render.Error(w, r, errs.BadRequestErr(err, "error reading request body"))
		return
	}
	if body.Confirmation == "" {
		render.Error(w, r, errs.BadRequest("confirmation is required; call the preview endpoint first"))
		return
	}

	auth, ok := mustAuthority(r.Context()).(batchRevocationAuthority)
	if !ok {
		render.Error(w, r, errs.NotImplemented("batch revocation is not supported"))
		return
	}
	result, err := auth.RevokeBatch(r.Context(), body.options())
	if err != nil {
		render.Error(w, r, err)
		return
	}
	render.JSON(w, r, result)
}
