package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"kscan/internal/finding"
)

// fakeServer serves /api/v2/findings/ from per-flag fingerprint lists,
// paginated like DefectDojo (limit/offset, count).
func fakeServer(t *testing.T, byFlag map[string][]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token secret" {
			http.Error(w, `{"detail":"Invalid token."}`, http.StatusForbidden)
			return
		}
		q := r.URL.Query()
		if r.URL.Path != "/api/v2/findings/" || q.Get("product_name") != "my-repo" {
			t.Errorf("unexpected request %s", r.URL)
		}
		var ids []string
		for flag, list := range byFlag {
			if q.Get(flag) == "true" {
				ids = list
			}
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))
		end := min(offset+limit, len(ids))
		var results []map[string]string
		for _, id := range ids[min(offset, end):end] {
			results = append(results, map[string]string{"unique_id_from_tool": id})
		}
		json.NewEncoder(w).Encode(map[string]any{"count": len(ids), "results": results})
	}))
}

func TestTriaged(t *testing.T) {
	var many []string
	for i := range pageSize + 3 {
		many = append(many, fmt.Sprintf("fp%04d", i))
	}
	srv := fakeServer(t, map[string][]string{
		"false_p":       {"aaaa", ""}, // "" = a finding from another tool
		"risk_accepted": many,
		"out_of_scope":  {"cccc"},
	})
	defer srv.Close()

	got, err := New(srv.URL+"/", "secret").Triaged(context.Background(), "my-repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != pageSize+3+2 {
		t.Fatalf("got %d triaged, want %d (pagination?)", len(got), pageSize+5)
	}
	if got["aaaa"] != FalsePositive || got["cccc"] != OutOfScope || got[many[pageSize+2]] != RiskAccepted {
		t.Errorf("wrong statuses: aaaa=%q cccc=%q last=%q", got["aaaa"], got["cccc"], got[many[pageSize+2]])
	}
	if _, ok := got[""]; ok {
		t.Error("findings without a fingerprint must be ignored")
	}
}

func TestTriagedBadToken(t *testing.T) {
	srv := fakeServer(t, nil)
	defer srv.Close()
	_, err := New(srv.URL, "wrong").Triaged(context.Background(), "my-repo")
	if err == nil {
		t.Fatal("expected an error for a rejected token")
	}
}

func TestApply(t *testing.T) {
	fs := []finding.Finding{
		{Fingerprint: "aaaa", New: true},
		{Fingerprint: "bbbb", New: true},
	}
	if n := Apply(fs, map[string]string{"aaaa": FalsePositive}); n != 1 {
		t.Fatalf("Apply marked %d, want 1", n)
	}
	if fs[0].New || fs[0].Triage != FalsePositive {
		t.Errorf("triaged finding = %+v", fs[0])
	}
	if !fs[1].New || fs[1].Triage != "" {
		t.Errorf("untriaged finding changed: %+v", fs[1])
	}
}
