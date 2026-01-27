package domainconnect

import (
	"context"
	"errors"
	"net"
	"strings"
)

// lookupDomainConnectRecord looks up the _domainconnect TXT record for a domain.
// Returns the record value or ErrNoDomainConnectRecord if not found.
func lookupDomainConnectRecord(ctx context.Context, domain string) (string, error) {
	name := "_domainconnect." + domain
	resolver := net.DefaultResolver

	records, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return "", ErrNoDomainConnectRecord
		}
		return "", err
	}

	if len(records) == 0 {
		return "", ErrNoDomainConnectRecord
	}

	// TXT records can be split into multiple strings, join them
	return strings.Join(records, ""), nil
}
