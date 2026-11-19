package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/smallstep/certificates/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockRevocationAuthority struct {
	*mockAuthority
	snapshot *revocation.Snapshot
	err      error
}

func (m *mockRevocationAuthority) GetRevocationSnapshot(time.Time) (*revocation.Snapshot, error) {
	return m.snapshot, m.err
}

func Test_Revocations(t *testing.T) {
	now := time.Now().UTC()
	snapshot := &revocation.Snapshot{
		Version:       "sha256:test",
		GeneratedAt:   now,
		NextUpdate:    now.Add(5 * time.Second),
		CacheDuration: 2,
		FailurePolicy: revocation.FailClosed,
		Revocations: []revocation.Entry{{
			Serial:    "42",
			RevokedAt: now,
		}},
	}

	t.Run("ok", func(t *testing.T) {
		mockMustAuthority(t, &mockRevocationAuthority{
			mockAuthority: &mockAuthority{},
			snapshot:      snapshot,
		})

		req := httptest.NewRequest(http.MethodGet, "http://example.com/revocations", http.NoBody)
		w := httptest.NewRecorder()
		Revocations(w, req)
		res := w.Result()
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, `"sha256:test"`, res.Header.Get("ETag"))
		assert.Equal(t, "public, max-age=2", res.Header.Get("Cache-Control"))
		var got revocation.Snapshot
		require.NoError(t, json.NewDecoder(res.Body).Decode(&got))
		assert.Len(t, got.Revocations, 1)
	})

	t.Run("not modified", func(t *testing.T) {
		mockMustAuthority(t, &mockRevocationAuthority{
			mockAuthority: &mockAuthority{},
			snapshot:      snapshot,
		})

		req := httptest.NewRequest(http.MethodGet, "http://example.com/revocations", http.NoBody)
		req.Header.Set("If-None-Match", `"sha256:test"`)
		w := httptest.NewRecorder()
		Revocations(w, req)
		res := w.Result()
		defer res.Body.Close()

		assert.Equal(t, http.StatusNotModified, res.StatusCode)
	})

	t.Run("error", func(t *testing.T) {
		mockMustAuthority(t, &mockRevocationAuthority{
			mockAuthority: &mockAuthority{},
			err:           errors.New("force"),
		})

		req := httptest.NewRequest(http.MethodGet, "http://example.com/revocations", http.NoBody)
		w := httptest.NewRecorder()
		Revocations(w, req)
		res := w.Result()
		defer res.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
	})
}
