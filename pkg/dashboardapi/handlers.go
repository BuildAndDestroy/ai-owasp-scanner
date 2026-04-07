package dashboardapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/BuildAndDestroy/owasp-scanner/pkg/models"
)

const maxBodyBytes = 64 << 20 // 64 MiB

// Handler serves REST endpoints for the dashboard API.
type Handler struct {
	Store *Store
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// PostReport accepts a full scan report JSON body (same shape as reports/scan_report_*.json).
func (h *Handler) PostReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var report models.ScanReport
	if err := json.Unmarshal(body, &report); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	id, err := h.Store.InsertReport(r.Context(), &report)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"id":"` + id.Hex() + `"}`))
}

// ListReports GET /api/reports
func (h *Handler) ListReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	items, err := h.Store.ListReports(r.Context(), 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(items); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// GetReport GET /api/reports/{id}
func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/reports/")
	id = strings.TrimSuffix(id, "/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	rep, err := h.Store.GetReport(r.Context(), id)
	if err != nil {
		if err == ErrNotFound {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(rep); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// GetTechnologies GET /api/reports/{id}/technologies
func (h *Handler) GetTechnologies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/reports/")
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "technologies" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	id := parts[0]
	rep, err := h.Store.GetReport(r.Context(), id)
	if err != nil {
		if err == ErrNotFound {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := AggregateTechnologies(*rep)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// RegisterRoutes attaches handlers to the given mux under /api and /health.
func RegisterRoutes(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("/health", h.Health)
	mux.HandleFunc("/api/reports", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.ListReports(w, r)
		case http.MethodPost:
			h.PostReport(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/reports/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/technologies") {
			h.GetTechnologies(w, r)
			return
		}
		h.GetReport(w, r)
	})
}
