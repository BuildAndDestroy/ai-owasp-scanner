package dashboardapi

import (
	"sort"
	"strings"

	"github.com/BuildAndDestroy/owasp-scanner/pkg/models"
)

// TechnologyStat is a single aggregated technology observation.
type TechnologyStat struct {
	Name        string   `json:"name"`
	Version     string   `json:"version,omitempty"`
	Details     string   `json:"details,omitempty"`
	Source      string   `json:"source,omitempty"`
	PageCount   int      `json:"page_count"`
	ExampleURLs []string `json:"example_urls,omitempty"`
}

// ReportSummary is a lightweight view for list cards.
type ReportSummary struct {
	TargetURL         string `json:"target_url"`
	PagesScanned      int    `json:"pages_scanned"`
	PayloadsUsed      int    `json:"payloads_used"`
	ScanEndTime       string `json:"scan_end_time,omitempty"`
	TotalDurationText string `json:"total_duration_text,omitempty"`
	UniqueTechCount   int    `json:"unique_technology_count"`
}

// TechnologiesResponse is returned by GET .../technologies.
type TechnologiesResponse struct {
	Summary      ReportSummary    `json:"summary"`
	Technologies []TechnologyStat `json:"technologies"`
}

const maxExampleURLs = 5

// AggregateTechnologies rolls up software entries across all result URLs.
func AggregateTechnologies(r models.ScanReport) TechnologiesResponse {
	type key struct {
		name, version, details, source string
	}
	buckets := make(map[key]*TechnologyStat)

	for _, res := range r.Results {
		for _, sw := range res.Software {
			k := key{
				name:    strings.TrimSpace(sw.Name),
				version: strings.TrimSpace(sw.Version),
				details: strings.TrimSpace(sw.Details),
				source:  strings.TrimSpace(sw.Source),
			}
			if k.name == "" {
				continue
			}
			st, ok := buckets[k]
			if !ok {
				st = &TechnologyStat{
					Name:    k.name,
					Version: k.version,
					Details: k.details,
					Source:  k.source,
				}
				buckets[k] = st
			}
			st.PageCount++
			if len(st.ExampleURLs) < maxExampleURLs {
				st.ExampleURLs = append(st.ExampleURLs, res.URL)
			}
		}
	}

	out := make([]TechnologyStat, 0, len(buckets))
	for _, st := range buckets {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PageCount != out[j].PageCount {
			return out[i].PageCount > out[j].PageCount
		}
		return out[i].Name < out[j].Name
	})

	return TechnologiesResponse{
		Summary: ReportSummary{
			TargetURL:         r.TargetURL,
			PagesScanned:      r.PagesScanned,
			PayloadsUsed:      r.PayloadsUsed,
			ScanEndTime:       r.ScanEndTime.Format("2006-01-02T15:04:05Z07:00"),
			TotalDurationText: r.TotalDuration.String(),
			UniqueTechCount:   len(out),
		},
		Technologies: out,
	}
}
