package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/revocation"
)

type revocationSnapshotAuthority interface {
	GetRevocationSnapshot(time.Time) (*revocation.Snapshot, error)
}

// Revocations returns the current short-lived certificate revocation snapshot.
func Revocations(w http.ResponseWriter, r *http.Request) {
	auth, ok := mustAuthority(r.Context()).(revocationSnapshotAuthority)
	if !ok {
		render.Error(w, r, errs.NotImplemented("revocation snapshots are not supported"))
		return
	}

	snapshot, err := auth.GetRevocationSnapshot(time.Now())
	if err != nil {
		render.Error(w, r, err)
		return
	}

	etag := `"` + snapshot.Version + `"`
	w.Header().Set("ETag", etag)
	if snapshot.CacheDuration > 0 {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", snapshot.CacheDuration))
		w.Header().Set("Expires", snapshot.GeneratedAt.Add(time.Duration(snapshot.CacheDuration)*time.Second).Format(time.RFC1123))
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	render.JSON(w, r, snapshot)
}

func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag {
			return true
		}
	}
	return false
}
