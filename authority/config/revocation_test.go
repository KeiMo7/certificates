package config

import (
	"testing"
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRevocationConfigInitAndValidate(t *testing.T) {
	cfg := &RevocationConfig{Enabled: true}
	cfg.Init()
	assert.Equal(t, DefaultRevocationRefreshInterval, cfg.PollInterval())
	assert.Equal(t, DefaultRevocationCacheDuration, cfg.CacheTTL())
	assert.Equal(t, DefaultRevocationCleanupInterval, cfg.CleanupEvery())
	assert.Equal(t, revocation.FailClosed, cfg.FailurePolicy)
	require.NoError(t, cfg.Validate())

	cfg = &RevocationConfig{
		Enabled:         true,
		RefreshInterval: &provisioner.Duration{Duration: time.Second},
		CacheDuration:   &provisioner.Duration{Duration: 500 * time.Millisecond},
		CleanupInterval: &provisioner.Duration{Duration: time.Minute},
		Retention:       &provisioner.Duration{Duration: time.Hour},
		FailurePolicy:   revocation.FailOpen,
	}
	require.NoError(t, cfg.Validate())
}

func TestRevocationConfigValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  *RevocationConfig
		err  string
	}{
		{
			name: "refresh",
			cfg:  &RevocationConfig{RefreshInterval: &provisioner.Duration{}},
			err:  "revocation.refreshInterval must be greater than 0",
		},
		{
			name: "cache",
			cfg:  &RevocationConfig{CacheDuration: &provisioner.Duration{Duration: -time.Second}},
			err:  "revocation.cacheDuration must be greater than or equal to 0",
		},
		{
			name: "cleanup",
			cfg:  &RevocationConfig{CleanupInterval: &provisioner.Duration{}},
			err:  "revocation.cleanupInterval must be greater than 0",
		},
		{
			name: "retention",
			cfg:  &RevocationConfig{Retention: &provisioner.Duration{Duration: -time.Second}},
			err:  "revocation.retention must be greater than or equal to 0",
		},
		{
			name: "policy",
			cfg:  &RevocationConfig{FailurePolicy: "allow"},
			err:  `invalid revocation failure policy "allow"`,
		},
		{
			name: "cache exceeds refresh",
			cfg: &RevocationConfig{
				Enabled:         true,
				RefreshInterval: &provisioner.Duration{Duration: time.Second},
				CacheDuration:   &provisioner.Duration{Duration: 2 * time.Second},
			},
			err: "revocation.cacheDuration must be less than or equal to revocation.refreshInterval",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.err)
		})
	}
}
