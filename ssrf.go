package domainconnect

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
)

// newGuardedHTTPClient returns an HTTP client that refuses to connect to
// non-public IP addresses.
//
// Domain Connect discovery follows an untrusted chain: a domain's
// _domainconnect TXT record names the settings host, and that host's settings
// JSON supplies urlAPI. A caller who controls a domain's DNS can therefore
// steer these fetches at internal services or cloud metadata, so without a
// guard the discovery path is a server-side request forgery primitive.
//
// The check runs in the dialer's Control hook, which fires after DNS
// resolution on the concrete IP about to be dialed. That placement also covers
// HTTP redirects and DNS rebinding, since every connection attempt is checked
// against its resolved address rather than the hostname.
func newGuardedHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("%w: %q", ErrBlockedAddress, address)
			}
			if !isPublicIP(ip) {
				return fmt.Errorf("%w: %s", ErrBlockedAddress, ip)
			}
			return nil
		},
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext

	return &http.Client{Transport: transport}
}

// isPublicIP reports whether ip is a globally routable address safe to fetch
// from. Loopback, private, link-local (including cloud metadata at
// 169.254.169.254), multicast, unspecified, and carrier-grade NAT ranges are
// all rejected.
func isPublicIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}

	// Carrier-grade NAT (100.64.0.0/10) is not covered by IsPrivate.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return false
	}

	return true
}
