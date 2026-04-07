package dashboardapi

import (
	"testing"
	"time"

	"github.com/BuildAndDestroy/owasp-scanner/pkg/models"
)

func TestAggregateTechnologies(t *testing.T) {
	r := models.ScanReport{
		TargetURL:     "https://example.com",
		ScanEndTime:   time.Date(2026, 4, 7, 12, 0, 0, 0, time.UTC),
		TotalDuration: time.Minute,
		PagesScanned:  2,
		Results: []models.ScanResult{
			{
				URL: "https://example.com/a",
				Software: []models.SoftwareInfo{
					{Name: "Server", Details: "nginx", Source: "header:Server"},
					{Name: "TLS", Version: "TLS1.3", Source: "tls"},
				},
			},
			{
				URL: "https://example.com/b",
				Software: []models.SoftwareInfo{
					{Name: "Server", Details: "nginx", Source: "header:Server"},
				},
			},
		},
	}
	out := AggregateTechnologies(r)
	if out.Summary.UniqueTechCount != 2 {
		t.Fatalf("unique tech count: got %d want 2", out.Summary.UniqueTechCount)
	}
	if len(out.Technologies) != 2 {
		t.Fatalf("technologies len: got %d want 2", len(out.Technologies))
	}
	if out.Technologies[0].Name != "Server" || out.Technologies[0].PageCount != 2 {
		t.Fatalf("first stat: %+v", out.Technologies[0])
	}
}
