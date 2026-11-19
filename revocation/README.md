# Short-lived certificate revocation feed

This package adds a pull-based revocation channel for short-lived X.509
certificates. It is optional and disabled by default; existing CRL and OCSP
behavior is unchanged.

## Delivery choice

The feed is polled over HTTPS:

- Edge verifiers do not need an inbound connection or a long-lived connection
  state.
- Every response is a complete snapshot, so a verifier that missed updates can
  recover with one request.
- `ETag` and `If-None-Match` keep the steady-state cost low.
- The CA advertises `refreshInterval`; verifiers can still use a different
  cadence based on their deployment and certificate lifetime.

Long-lived push connections were intentionally not used. They improve immediate
delivery but require connection state and do not work for edge nodes that cannot
connect back to a central service.

## Server configuration

```json
{
  "revocation": {
    "enabled": true,
    "refreshInterval": "10s",
    "cacheDuration": "5s",
    "cleanupInterval": "1m",
    "retention": "5m",
    "failurePolicy": "fail-closed"
  }
}
```

- `refreshInterval`: recommended polling cadence. Match this to the
  certificate lifetime rather than the CRL schedule.
- `cacheDuration`: maximum snapshot age advertised to verifiers.
- `cleanupInterval`: how often expired records are removed.
- `retention`: optional audit grace period after the certificate expires.
- `failurePolicy`: recommended verifier behavior when status cannot be
  confirmed. `fail-closed` is the default.

The feed is available at `GET /revocations` and `GET /1.0/revocations`. The
response is a full snapshot with a stable `ETag`, `Cache-Control`, and a
`nextUpdate` timestamp. Expired certificate records are omitted.

## Batch revocation

Batch revocation is exposed through the Admin API and always uses a
preview/confirm flow.

1. Preview:

```http
POST /admin/revocations/batch/preview
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "serials": ["1001", "1002", "1003"],
  "reasonCode": 4,
  "reason": "host compromise"
}
```

2. Commit the exact previewed set:

```http
POST /admin/revocations/batch
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "serials": ["1001", "1002", "1003"],
  "reasonCode": 4,
  "reason": "host compromise",
  "confirmation": "sha256:..."
}
```

The confirmation is a digest of the normalized, sorted serial list plus the
revocation reason. Changing the list, reason, or reason code after preview
rejects the request. Unknown or already-expired serials reject the whole batch.
Already-revoked serials are reported by the preview and are idempotent at
commit time.

The local NoSQL database writes all new records in one transaction and
preflights every serial before writing. A linked CA backend must explicitly
implement the batch interface; otherwise the request fails before any local
records are written.

## Verifier usage

Use the existing X.509 chain/signature validation first, then call
`revocation.Client.Check`:

```go
client, err := revocation.NewClient("https://ca.example.com/1.0/revocations", revocation.ClientOptions{
    RefreshInterval: 10 * time.Second,
    MaxAge:          30 * time.Second,
    FailurePolicy:   revocation.FailClosed,
})
if err != nil {
    return err
}

go client.Run(ctx)

if err := client.Check(cert); err != nil {
    // ErrRevoked or ErrUnavailable
}
```

- `MaxAge` controls how long a local snapshot remains usable.
- `FailOpen` allows traffic when status cannot be confirmed.
- `FailClosed` rejects traffic when status cannot be confirmed.
- An expired certificate is allowed to fall back to natural expiry.
- `Stats()` exposes checks, allow/deny counts, degraded events, and refresh
  failures for acceptance measurements.

## Acceptance test

```sh
go test ./authority -run TestBatchRevocationPropagationAcceptance -v
```

The test revokes 50 certificates against a real Badger database, runs three
independent polling verifiers, and logs the maximum propagation latency,
requests allowed during propagation, and record growth/cleanup.
