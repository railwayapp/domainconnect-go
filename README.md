# domainconnect-go

[![CI](https://github.com/railwayapp/domainconnect-go/actions/workflows/ci.yml/badge.svg)](https://github.com/railwayapp/domainconnect-go/actions/workflows/ci.yml)

Go implementation of the [Domain Connect](https://www.domainconnect.org/) protocol.

Port of [domainconnect_python](https://github.com/Domain-Connect/domainconnect_python).

## Installation

```bash
go get github.com/railwayapp/domainconnect-go
```

## Usage

### Sync Flow

```go
package main

import (
    "context"
    "fmt"
    "log"

    dc "github.com/railwayapp/domainconnect-go"
)

func main() {
    client := dc.New()
    ctx := context.Background()

    // Get domain configuration
    cfg, err := client.GetDomainConfig(ctx, "example.com")
    if err != nil {
        log.Fatal(err)
    }

    // Generate sync URL for user to visit
    url, err := client.GetSyncURL(ctx, dc.SyncURLOptions{
        Config:      cfg,
        ProviderID:  "yourprovider.com",
        ServiceID:   "yourtemplate",
        Params:      map[string]string{"IP": "1.2.3.4"},
        RedirectURL: "https://yourapp.com/callback",
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Direct user to: %s\n", url)
}
```

### Async Flow (OAuth)

```go
package main

import (
    "context"
    "fmt"
    "log"

    dc "github.com/railwayapp/domainconnect-go"
)

func main() {
    client := dc.New()
    ctx := context.Background()

    // Get domain configuration
    cfg, err := client.GetDomainConfig(ctx, "example.com")
    if err != nil {
        log.Fatal(err)
    }

    // Create async context with consent URL
    asyncCtx, err := client.GetAsyncContext(ctx, dc.AsyncContextOptions{
        Config:      cfg,
        ProviderID:  "yourprovider.com",
        ServiceID:   "yourtemplate",
        RedirectURL: "https://yourapp.com/callback",
        State:       "mystate",
    })
    if err != nil {
        log.Fatal(err)
    }

    // Build consent URL with client ID
    consentURL := asyncCtx.BuildAsyncConsentURL("your-client-id", "")
    fmt.Printf("Direct user to: %s\n", consentURL)

    // After user authorizes, parse callback URL
    callbackURL := "https://yourapp.com/callback?code=authcode123&state=mystate"
    if err := asyncCtx.SetCodeFromCallback(callbackURL); err != nil {
        log.Fatal(err)
    }

    // Exchange code for token
    creds := dc.AsyncCredentials{
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
    }
    asyncCtx, err = client.GetAsyncToken(ctx, asyncCtx, creds)
    if err != nil {
        log.Fatal(err)
    }

    // Apply template
    err = client.ApplyAsync(ctx, asyncCtx, dc.ApplyAsyncOptions{
        Params: map[string]string{"IP": "1.2.3.4"},
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Template applied successfully")
}
```

### Custom HTTP Client

```go
client := dc.New(dc.WithHTTPClient(&http.Client{
    Timeout: 30 * time.Second,
}))
```

### Signed Requests

```go
privateKey, _ := os.ReadFile("private_key.pem")

url, err := client.GetSyncURL(ctx, dc.SyncURLOptions{
    Config:     cfg,
    ProviderID: "yourprovider.com",
    ServiceID:  "yourtemplate",
    Params:     map[string]string{"IP": "1.2.3.4"},
    PrivateKey: privateKey,
    KeyID:      "1",
})
```

## API Reference

### Types

- `Client` - Domain Connect client
- `Config` - Domain configuration (provider URLs, etc.)
- `AsyncContext` - State for async OAuth flow
- `AsyncCredentials` - OAuth client credentials

### Client Methods

| Method | Description |
|--------|-------------|
| `New(opts...)` | Create new client |
| `GetDomainConfig(ctx, domain)` | Discover Domain Connect settings |
| `CheckTemplateSupported(ctx, cfg, providerID, serviceIDs)` | Verify template support |
| `GetSyncURL(ctx, opts)` | Generate sync apply URL |
| `GetAsyncContext(ctx, opts)` | Create async OAuth context |
| `GetAsyncToken(ctx, asyncCtx, creds)` | Exchange auth code for token |
| `RefreshAsyncToken(ctx, asyncCtx, creds)` | Refresh expired token |
| `ApplyAsync(ctx, asyncCtx, opts)` | Apply template with OAuth |
| `DeleteAsync(ctx, asyncCtx, serviceID)` | Remove applied template |

### Helper Functions

| Function | Description |
|----------|-------------|
| `IdentifyDomainRoot(domain)` | Extract registrable domain (eTLD+1) |
| `ParseCallbackURL(url)` | Extract code/state from OAuth callback |
| `ServiceIDsFromCallback(url)` | Extract granted service IDs |

## Differences from Python Library

- No custom nameserver support (uses system resolver)
- No proxy configuration (pass custom `http.Client` instead)
- Context-based cancellation support

## License

MIT - see [LICENSE](LICENSE)
