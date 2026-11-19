package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/smallstep/certificates/authority"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockBatchAdminAuthority struct {
	*mockAdminAuthority
	preview *authority.RevokeBatchPreview
	result  *authority.RevokeBatchResult
	err     error
	opts    *authority.RevokeBatchOptions
}

func (m *mockBatchAdminAuthority) PreviewRevokeBatch(_ context.Context, opts *authority.RevokeBatchOptions) (*authority.RevokeBatchPreview, error) {
	m.opts = opts
	return m.preview, m.err
}

func (m *mockBatchAdminAuthority) RevokeBatch(_ context.Context, opts *authority.RevokeBatchOptions) (*authority.RevokeBatchResult, error) {
	m.opts = opts
	return m.result, m.err
}

func TestPreviewRevokeBatch(t *testing.T) {
	auth := &mockBatchAdminAuthority{
		mockAdminAuthority: &mockAdminAuthority{},
		preview: &authority.RevokeBatchPreview{
			Confirmation: "sha256:test",
			Total:        2,
			Affected:     2,
		},
	}
	mockMustAuthority(t, auth)

	body := `{"serials":["1","2"],"reasonCode":4,"reason":"host compromise"}`
	req := httptest.NewRequest(http.MethodPost, "http://example.com/admin/revocations/batch/preview", strings.NewReader(body))
	w := httptest.NewRecorder()
	PreviewRevokeBatch(w, req)
	res := w.Result()
	defer res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)
	var got authority.RevokeBatchPreview
	require.NoError(t, json.NewDecoder(res.Body).Decode(&got))
	assert.Equal(t, "sha256:test", got.Confirmation)
	require.NotNil(t, auth.opts)
	assert.Equal(t, []string{"1", "2"}, auth.opts.Serials)
}

func TestRevokeBatch(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		auth := &mockBatchAdminAuthority{
			mockAdminAuthority: &mockAdminAuthority{},
			result:             &authority.RevokeBatchResult{Status: "ok", Revoked: 2},
		}
		mockMustAuthority(t, auth)

		body := `{"serials":["1","2"],"reasonCode":4,"confirmation":"sha256:test"}`
		req := httptest.NewRequest(http.MethodPost, "http://example.com/admin/revocations/batch", strings.NewReader(body))
		w := httptest.NewRecorder()
		RevokeBatch(w, req)
		res := w.Result()
		defer res.Body.Close()

		require.Equal(t, http.StatusOK, res.StatusCode)
		require.NotNil(t, auth.opts)
		assert.Equal(t, "sha256:test", auth.opts.Confirmation)
	})

	t.Run("missing confirmation", func(t *testing.T) {
		mockMustAuthority(t, &mockBatchAdminAuthority{mockAdminAuthority: &mockAdminAuthority{}})

		body := `{"serials":["1"],"reasonCode":4}`
		req := httptest.NewRequest(http.MethodPost, "http://example.com/admin/revocations/batch", strings.NewReader(body))
		w := httptest.NewRecorder()
		RevokeBatch(w, req)
		res := w.Result()
		defer res.Body.Close()

		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("authority error", func(t *testing.T) {
		mockMustAuthority(t, &mockBatchAdminAuthority{
			mockAdminAuthority: &mockAdminAuthority{},
			err:                errors.New("force"),
		})

		body := `{"serials":["1"],"reasonCode":4,"confirmation":"sha256:test"}`
		req := httptest.NewRequest(http.MethodPost, "http://example.com/admin/revocations/batch", strings.NewReader(body))
		w := httptest.NewRecorder()
		RevokeBatch(w, req)
		res := w.Result()
		defer res.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
	})
}
