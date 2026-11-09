// Package defectdojo reads triage decisions (false positive, risk accepted,
// out of scope) from a DefectDojo server, so findings triaged there no
// longer fail a scan.
package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"kscan/internal/finding"
)

// Triage values, matching DefectDojo's finding flags.
const (
	FalsePositive = "false_positive"
	RiskAccepted  = "risk_accepted"
	OutOfScope    = "out_of_scope"
)

// flags maps each triage value to the DefectDojo API filter that selects it.
var flags = []struct{ status, filter string }{
	{FalsePositive, "false_p"},
	{RiskAccepted, "risk_accepted"},
	{OutOfScope, "out_of_scope"},
}

const pageSize = 500

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type page struct {
	Count   int `json:"count"`
	Results []struct {
		UniqueID string `json:"unique_id_from_tool"`
	} `json:"results"`
}

// Triaged returns fingerprint -> triage status for every finding of the
// product that DefectDojo marks false positive, risk accepted or out of
// scope. Findings without a kscan fingerprint (other tools) are ignored.
// DefectDojo un-sets risk_accepted itself when an acceptance expires.
func (c *Client) Triaged(ctx context.Context, product string) (map[string]string, error) {
	out := map[string]string{}
	for _, fl := range flags {
		for offset := 0; ; offset += pageSize {
			q := url.Values{
				"product_name": {product},
				fl.filter:      {"true"},
				"limit":        {strconv.Itoa(pageSize)},
				"offset":       {strconv.Itoa(offset)},
			}
			var p page
			if err := c.get(ctx, "/api/v2/findings/?"+q.Encode(), &p); err != nil {
				return nil, err
			}
			for _, r := range p.Results {
				if r.UniqueID != "" {
					out[r.UniqueID] = fl.status
				}
			}
			if len(p.Results) < pageSize || offset+pageSize >= p.Count {
				break
			}
		}
	}
	return out, nil
}

func (c *Client) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+c.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("defectdojo: GET %s: %s: %s", strings.SplitN(path, "?", 2)[0], resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// Apply marks triaged findings as not new, so the gate ignores them, and
// records why. It returns how many findings it marked.
func Apply(findings []finding.Finding, triaged map[string]string) int {
	n := 0
	for i := range findings {
		if st, ok := triaged[findings[i].Fingerprint]; ok {
			findings[i].Triage = st
			findings[i].New = false
			n++
		}
	}
	return n
}
