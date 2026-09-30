package compliance

import (
	"bytes"
	"encoding/csv"
	"html/template"
	"strings"
)

// StatusLabel is the Chinese name of a status.
func StatusLabel(s string) string {
	switch s {
	case Pass:
		return "符合"
	case Partial:
		return "部分符合"
	case Fail:
		return "不符合"
	default:
		return "需人工核查"
	}
}

// BasisLabel is the Chinese name of how a check was decided.
func BasisLabel(b string) string {
	switch b {
	case BasisLive:
		return "实时"
	case BasisCapability:
		return "能力"
	default:
		return "需人工"
	}
}

// CSV renders the checks as a spreadsheet-friendly file (UTF-8 with BOM so
// Excel shows Chinese correctly). Cells that start with a formula character
// are prefixed so that opening the file cannot execute anything.
func CSV(r Report) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\xEF\xBB\xBF")
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"分类", "编号", "检查项", "要求", "依据", "结论", "判定方式", "证据", "整改建议"})
	for _, sec := range r.Sections {
		for _, c := range sec.Checks {
			row := []string{c.Category, c.ID, c.Title, c.Requirement, c.Ref, StatusLabel(c.Status), BasisLabel(c.Basis), c.Evidence, c.Remediation}
			for i := range row {
				row[i] = neutralize(row[i])
			}
			_ = w.Write(row)
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// neutralize stops a cell from being read as a spreadsheet formula.
func neutralize(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"status": StatusLabel, "basis": BasisLabel,
	"date": func(r Report) string { return r.GeneratedAt.Local().Format("2006-01-02 15:04") },
}).Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{--pass:#168447;--partial:#b7791f;--fail:#c9352b;--manual:#64748b;--line:#d9e2ec;--muted:#64748b}
body{font:14px/1.6 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;color:#142033;margin:0;padding:32px 24px;background:#fff}
main{max-width:1000px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px;padding-bottom:6px;border-bottom:2px solid #142033}
.meta{color:var(--muted);margin-bottom:16px}
.note{border:1px solid var(--line);background:#f8fafc;padding:10px 14px;border-radius:6px;font-size:13px;color:#334155}
.demo{border-color:var(--partial);background:#fffbeb;color:#92400e;margin-bottom:12px}
.sum{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.sum div{flex:1;min-width:110px;border:1px solid var(--line);border-radius:8px;padding:10px 14px}
.sum b{display:block;font-size:24px}
.pass{color:var(--pass)}.partial{color:var(--partial)}.fail{color:var(--fail)}.manual{color:var(--manual)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{border:1px solid var(--line);padding:7px 9px;vertical-align:top;text-align:left}
th{background:#f1f5f9;white-space:nowrap}
td.st{white-space:nowrap;font-weight:700}
.ref,.basis{color:var(--muted);font-size:12px}
.fix{color:#334155}
tr{break-inside:avoid}
@media print{body{padding:0}h2{break-after:avoid}}
</style></head><body><main>
<h1>{{.Title}}</h1>
<div class="meta">生成时间 {{date .}}</div>
{{if .Demo}}<div class="note demo"><b>演示数据。</b>这份报告来自演示环境的示例数据，不代表任何真实系统。</div>{{end}}
<div class="note">{{.Disclaimer}}</div>
<div class="sum">
<div><b>{{.Summary.Total}}</b>检查项</div>
<div class="pass"><b>{{.Summary.Pass}}</b>符合</div>
<div class="partial"><b>{{.Summary.Partial}}</b>部分符合</div>
<div class="fail"><b>{{.Summary.Fail}}</b>不符合</div>
<div class="manual"><b>{{.Summary.Manual}}</b>需人工核查</div>
</div>
{{range .Sections}}<h2>{{.Category}}</h2>
<table><thead><tr><th>编号</th><th>检查项</th><th>结论</th><th>证据</th><th>整改建议</th></tr></thead><tbody>
{{range .Checks}}<tr>
<td>{{.ID}}</td>
<td><b>{{.Title}}</b><br>{{.Requirement}}<br><span class="ref">{{.Ref}}</span></td>
<td class="st {{.Status}}">{{status .Status}}<br><span class="basis">{{basis .Basis}}</span></td>
<td>{{.Evidence}}</td>
<td class="fix">{{.Remediation}}</td>
</tr>{{end}}</tbody></table>
{{end}}
</main></body></html>`))

// HTML renders a self-contained, printable report. All values are escaped.
func HTML(r Report) ([]byte, error) {
	var buf bytes.Buffer
	if err := htmlTmpl.Execute(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
