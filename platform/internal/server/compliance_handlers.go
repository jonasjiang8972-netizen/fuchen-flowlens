package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/compliance"
)

// SetDeployment records how this instance was started (database, TLS, agent
// authentication), which the platform cannot observe about itself.
func (s *PlatformServer) SetDeployment(d compliance.Deployment) { s.deployment = d }

// complianceSnapshot gathers the live state the report is built from.
func (s *PlatformServer) complianceSnapshot(ctx context.Context) (compliance.Snapshot, error) {
	users, err := s.iam.ListUsers(ctx)
	if err != nil {
		return compliance.Snapshot{}, fmt.Errorf("list users: %w", err)
	}
	snap := compliance.Snapshot{
		Policy: s.iam.Policy(ctx), Users: users, Deploy: s.deployment,
		Assets: s.assetService.List(), Alerts: s.alertService.List(), Tickets: s.ticketService.Summary(),
		Agents: s.agentService.List(), Rules: s.ruleService.List(),
	}
	for _, a := range snap.Alerts {
		if (a.Severity == "high" || a.Severity == "critical") && (a.Status == "open" || a.Status == "acknowledged") &&
			s.ticketService.ForAlert(a.ID) == nil {
			snap.SeriousAlertsWithoutTicket++
		}
	}
	for _, c := range s.soar.Connectors() {
		if c.Name != "simulator" {
			snap.Deploy.SOARConnectors++
		}
	}
	snap.Deploy.SOARDryRun = s.soar.Policy().DryRun
	ml := s.bolaEngine.MLStatus()
	snap.Deploy.BOLAModelEnabled, snap.Deploy.BOLAModelTrained = ml.Enabled, ml.Trained
	snap.Deploy.DemoMode = s.DemoMode

	res, err := s.audit.VerifyIncremental(ctx)
	if err != nil {
		snap.AuditErr = err.Error()
	} else {
		snap.AuditCheck = &res
	}
	return snap, nil
}

func (s *PlatformServer) buildReport(c *gin.Context) (compliance.Report, bool) {
	snap, err := s.complianceSnapshot(c.Request.Context())
	if err != nil {
		respondErr(c, err)
		return compliance.Report{}, false
	}
	template := c.DefaultQuery("template", compliance.TemplateMLPS3)
	r, err := compliance.Build(template, snap)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return compliance.Report{}, false
	}
	return r, true
}

// ComplianceTemplatesHandler lists the report templates.
func (s *PlatformServer) ComplianceTemplatesHandler(c *gin.Context) {
	c.JSON(200, gin.H{"items": compliance.Templates()})
}

// ComplianceReportHandler generates a report as JSON.
//
//	GET /reports/compliance?template=mlps3|finance
func (s *PlatformServer) ComplianceReportHandler(c *gin.Context) {
	r, ok := s.buildReport(c)
	if !ok {
		return
	}
	s.auditAction(c, "report.generate", r.Template, audit.ResultSuccess, "",
		fmt.Sprintf("pass=%d partial=%d fail=%d manual=%d", r.Summary.Pass, r.Summary.Partial, r.Summary.Fail, r.Summary.Manual))
	c.JSON(200, r)
}

// ComplianceExportHandler downloads a report as a printable HTML page or CSV.
//
//	GET /reports/compliance/export?template=&format=html|csv
func (s *PlatformServer) ComplianceExportHandler(c *gin.Context) {
	format := c.DefaultQuery("format", "html")
	if format != "html" && format != "csv" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "format 必须是 html 或 csv"})
		return
	}
	r, ok := s.buildReport(c)
	if !ok {
		return
	}
	var body []byte
	var err error
	var ctype string
	if format == "csv" {
		body, err = compliance.CSV(r)
		ctype = "text/csv; charset=utf-8"
	} else {
		body, err = compliance.HTML(r)
		ctype = "text/html; charset=utf-8"
	}
	if err != nil {
		respondErr(c, err)
		return
	}
	// A report leaves the platform as a file: record who took it.
	s.auditAction(c, "report.export", r.Template, audit.ResultSuccess, "", "format="+format)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"flowlens-%s-%s.%s\"", r.Template, r.GeneratedAt.Format("20060102-1504"), format))
	c.Header("Cache-Control", "no-store")
	c.Data(200, ctype, body)
}
