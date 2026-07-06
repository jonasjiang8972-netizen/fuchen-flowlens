package server

import "github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"

func countBySensitivity(assets []service.Asset, s string) int {
	count := 0
	for _, a := range assets {
		if a.SensitivityHint == s {
			count++
		}
	}
	return count
}

func countByStatus(assets []service.Asset, s string) int {
	count := 0
	for _, a := range assets {
		if a.Status == s {
			count++
		}
	}
	return count
}

func countByClaim(assets []service.Asset, s string) int {
	count := 0
	for _, a := range assets {
		if a.ClaimStatus == s {
			count++
		}
	}
	return count
}

func countBySeverity(alerts []service.Alert, s string) int {
	count := 0
	for _, a := range alerts {
		if a.Severity == s {
			count++
		}
	}
	return count
}

func countByAlertStatus(alerts []service.Alert, s string) int {
	count := 0
	for _, a := range alerts {
		if a.Status == s {
			count++
		}
	}
	return count
}

