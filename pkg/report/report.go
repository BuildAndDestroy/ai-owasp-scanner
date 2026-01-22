package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/BuildAndDestroy/owasp-scanner/pkg/models"
)

// Generate creates a scan report from results
func Generate(targetURL string, startTime, endTime time.Time, results []models.ScanResult, pagesScanned, payloadsUsed int) models.ScanReport {
	report := models.ScanReport{
		TargetURL:     targetURL,
		ScanStartTime: startTime,
		ScanEndTime:   endTime,
		TotalDuration: endTime.Sub(startTime),
		PagesScanned:  pagesScanned,
		PayloadsUsed:  payloadsUsed,
		Results:       results,
	}

	// Count findings by confidence level
	for _, result := range results {
		for _, finding := range result.Findings {
			switch finding.Confidence {
			case models.ConfidenceHigh:
				report.HighConfidence++
			case models.ConfidenceMedium:
				report.MediumConfidence++
			case models.ConfidenceLow:
				report.LowConfidence++
			case models.ConfidencePlausible:
				report.PlausibleFindings++
			}
		}

		for _, payload := range result.PayloadTests {
			if payload.ExploitDetected {
				report.ConfirmedExploits++
			}
		}
	}

	return report
}

// SaveJSON saves the report as a JSON file with timestamp
func SaveJSON(report models.ScanReport) error {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("scan_report_%s.json", timestamp)

	// Determine report directory - prefer /app/reports for Docker, fall back to reports/
	reportDir := "reports"
	if _, err := os.Stat("/app/reports"); err == nil {
		reportDir = "/app/reports"
	}

	// Create reports directory if it doesn't exist
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}

	filepath := fmt.Sprintf("%s/%s", reportDir, filename)

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(filepath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("\n✓ JSON report saved to: %s\n", filepath)
	printSummaryStats(report)

	return nil
}

// PrintConsole outputs the report to console
func PrintConsole(report models.ScanReport) {
	fmt.Println("\n========================================")
	fmt.Println("SCAN COMPLETE - SUMMARY")
	fmt.Println("========================================")
	printSummaryStats(report)
	fmt.Println()

	if len(report.Results) == 0 {
		fmt.Println("✓ No vulnerabilities found across all scanned pages!")
		return
	}

	// Print confirmed exploits first
	if report.ConfirmedExploits > 0 {
		printExploits(report)
	}

	// Print findings by confidence
	printFindingsByConfidence(report, models.ConfidenceHigh, "⚠️  HIGH CONFIDENCE FINDINGS:")
	printFindingsByConfidence(report, models.ConfidenceMedium, "⚡ MEDIUM CONFIDENCE FINDINGS:")
	printFindingsByConfidence(report, models.ConfidenceLow, "⚪ LOW CONFIDENCE FINDINGS:")
	printFindingsByConfidence(report, models.ConfidencePlausible, "💭 PLAUSIBLE FINDINGS:")
}

// printSummaryStats prints summary statistics
func printSummaryStats(report models.ScanReport) {
	fmt.Printf("Target: %s\n", report.TargetURL)
	fmt.Printf("Scan Duration: %v\n", report.TotalDuration)
	fmt.Printf("Pages Scanned: %d\n", report.PagesScanned)
	fmt.Printf("Payloads Tested: %d\n\n", report.PayloadsUsed)

	fmt.Println("Finding Summary:")
	fmt.Printf("  🚨 Confirmed Exploits: %d\n", report.ConfirmedExploits)
	fmt.Printf("  ⚠️  High Confidence: %d\n", report.HighConfidence)
	fmt.Printf("  ⚡ Medium Confidence: %d\n", report.MediumConfidence)
	fmt.Printf("  ⚪ Low Confidence: %d\n", report.LowConfidence)
	fmt.Printf("  💭 Plausible: %d\n", report.PlausibleFindings)
}

// printExploits prints confirmed exploits
func printExploits(report models.ScanReport) {
	fmt.Println("\n🚨 CONFIRMED EXPLOITS:")
	fmt.Println("=====================================")

	for i, result := range report.Results {
		hasExploits := false
		for _, payload := range result.PayloadTests {
			if payload.ExploitDetected {
				if !hasExploits {
					fmt.Printf("\n[%d] URL: %s\n", i+1, result.URL)
					hasExploits = true
				}
				fmt.Printf("  ✗ EXPLOIT: %s\n", payload.Payload)
				fmt.Printf("    Confidence: %s\n", payload.Confidence)
				for _, indicator := range payload.Indicators {
					fmt.Printf("    - %s\n", indicator)
				}
			}
		}
	}
}

// printFindingsByConfidence prints findings of a specific confidence level
func printFindingsByConfidence(report models.ScanReport, confidence models.ConfidenceLevel, header string) {
	fmt.Printf("\n%s\n", header)
	fmt.Println("=====================================")

	count := 0
	for i, result := range report.Results {
		printed := false
		for _, finding := range result.Findings {
			if finding.Confidence == confidence {
				if !printed {
					fmt.Printf("\n[%d] URL: %s\n", i+1, result.URL)
					printed = true
					count++
				}
				fmt.Printf("  %s [%s]\n", finding.Category, finding.Severity)
				fmt.Printf("    %s\n", finding.Description)
				fmt.Printf("    Evidence: %s\n", finding.Evidence)
			}
		}
	}

	if count == 0 {
		fmt.Println("  None found")
	}
}
