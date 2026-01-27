package domainconnect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ensureScheme adds https:// prefix if not already present.
func ensureScheme(urlStr string) string {
	if strings.HasPrefix(urlStr, "https://") || strings.HasPrefix(urlStr, "http://") {
		return urlStr
	}
	return "https://" + urlStr
}

func (c *Client) doJSON(ctx context.Context, method, urlStr string, result any) error {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("HTTP %d (failed to read body: %v)", resp.StatusCode, err)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(result)
}

func (c *Client) postForm(ctx context.Context, urlStr string, data url.Values, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, nil)
	if err != nil {
		return err
	}
	req.URL.RawQuery = data.Encode()
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("HTTP %d (failed to read body: %v)", resp.StatusCode, err)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(result)
}
