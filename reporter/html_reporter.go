// reporter/html_reporter.go
package reporter

import (
	"html/template"
	"os"
	"sort"

	"argus/analyzer"
)

// GenerateHTMLReport 根据报告数据生成一个HTML文件
func GenerateHTMLReport(report analyzer.Report, outputPath string) error {
	// 为了报告的美观，我们先对结果按依赖项名称排序
	sort.Slice(report.Results, func(i, j int) bool {
		return report.Results[i].Dependency.Name < report.Results[j].Dependency.Name
	})

	// 使用Go内置的模板引擎
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// 将报告数据渲染到模板中，并写入文件
	return tmpl.Execute(file, report)
}

// htmlTemplate 是嵌入在代码中的HTML模板字符串
const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Argus 安全扫描报告</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1, h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .summary { background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .card { border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card-header { background-color: #f2f2f2; padding: 15px; font-weight: bold; font-size: 1.2em; border-bottom: 1px solid #ddd; }
        .card-body { padding: 15px; }
        .vuln-item { border-bottom: 1px dashed #ccc; padding: 10px 0; }
        .vuln-item:last-child { border-bottom: none; }
        .vuln-id { font-weight: bold; color: #c0392b; }
        .ecosystem { background-color: #3498db; color: white; padding: 3px 8px; border-radius: 3px; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1><span class="ecosystem">Argus</span> 安全扫描报告</h1>
    <div class="summary">
        <p><strong>扫描时间:</strong> {{.Timestamp}}</p>
        <p><strong>发现漏洞的依赖项数量:</strong> {{len .Results}}</p>
    </div>

    {{range .Results}}
    <div class="card">
        <div class="card-header">
            <span class="ecosystem">{{.Dependency.Ecosystem}}</span> {{.Dependency.Name}} @ {{.Dependency.Version}}
        </div>
        <div class="card-body">
            <p><strong>发现于:</strong> {{.Dependency.File}}</p>
            <h4>发现 {{len .Vulnerabilities}} 个漏洞:</h4>
            {{range .Vulnerabilities}}
            <div class="vuln-item">
                <p><span class="vuln-id">{{.ID}}</span> ({{range .Aliases}}{{.}} {{end}})</p>
                <p><strong>摘要:</strong> {{if .Summary}}{{.Summary}}{{else}}(无可用摘要){{end}}</p>
            </div>
            {{end}}
        </div>
    </div>
    {{else}}
    <div class="summary" style="background-color: #d4edda;">
        <h2>恭喜！未发现任何已知漏洞。</h2>
    </div>
    {{end}}
</body>
</html>
`
