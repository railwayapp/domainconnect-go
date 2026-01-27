# domainconnect-go

Go port of [domainconnect_python](https://github.com/Domain-Connect/domainconnect_python).

## Commands

```bash
mise run setup  # go mod tidy
mise run test   # go test -v ./...
mise run lint   # go vet ./...
mise run fmt    # go fmt ./...
```

## Architecture

- `client.go` - Main client, Config type, sync URL generation
- `async.go` - OAuth flow (context, token exchange, apply)
- `dns.go` - `_domainconnect` TXT record lookup
- `signing.go` - RSA-SHA256 signature generation
- `http.go` - HTTP helpers, URL scheme normalization
- `errors.go` - Sentinel errors

## Testing

Tests run against real Domain Connect infrastructure (`diabtrack.com` via IONOS). No mocks.

Integration tests require network access - they hit real DNS and HTTPS endpoints.

## Notes

- Go 1.21+ required
- Single external dep: `golang.org/x/net/publicsuffix`
- Provider URLs may include scheme (`https://...`) or not - use `ensureScheme()` when building URLs
