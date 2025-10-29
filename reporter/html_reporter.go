// reporter/html_reporter.go
package reporter

import (
	"html/template"
	"os"
	"sort"
	"strings"

	"argus/analyzer"
)

// GenerateHTMLReport ... (函数本身不变)
func GenerateHTMLReport(report analyzer.Report, outputPath string) error {
	sort.Slice(report.Results, func(i, j int) bool {
		return report.Results[i].Dependency.Name < report.Results[j].Dependency.Name
	})
	funcMap := template.FuncMap{
		"TotalVulns": func(results []analyzer.Result) int {
			count := 0
			for _, r := range results {
				count += len(r.Vulnerabilities)
			}
			return count
		},
		"TrimSpace": strings.TrimSpace,
	}
	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()
	return tmpl.Execute(file, report)
}

// htmlTemplate 升级版
const htmlTemplate = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>Argus 安全扫描报告</title>
    <!-- 引入 jsPDF 和 html2canvas -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
    <style>
        /* ... (CSS样式保持不变) ... */
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #f8f9fa; }
        h1, h2, h3 { color: #2c3e50; }
        h1 { border-bottom: 3px solid #3498db; display: flex; justify-content: space-between; align-items: center; }
        h2 { border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; margin-top: 40px; }
        .summary { background-color: #ffffff; padding: 20px; border-radius: 8px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
        .card { border: 1px solid #ddd; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); background-color: #fff; overflow: hidden; }
        .card-header { background-color: #f7f7f7; padding: 15px 20px; font-weight: bold; font-size: 1.2em; border-bottom: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center; }
        .card-header.vuln-header { background-color: #fbeae5; }
        .card-header.vcsa-header { background-color: #d4e6f1; }
        .card-body { padding: 20px; }
        .vuln-item { border-bottom: 1px dashed #eee; padding: 15px 0; }
        .vuln-item:last-child { border-bottom: none; }
        .vuln-id { font-weight: bold; color: #c0392b; }
        .tag { color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.9em; }
        .tag-ecosystem { background-color: #3498db; }
        .tag-cwe { background-color: #9b59b6; }
        pre { background-color: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: "Courier New", Courier, monospace; }
        code { font-family: "Courier New", Courier, monospace; }
        .export-btn { background-color: #16a085; color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; }
        .export-btn:hover { background-color: #1abc9c; }
    </style>
</head>
<body>
    <div id="report-content">
        <h1>
            <span><span class="tag tag-ecosystem">Argus</span> 安全扫描报告</span>
            <button class="export-btn" onclick="exportPDF()">导出为 PDF</button>
        </h1>
        <div class="summary">
            <!-- ... (摘要内容不变) ... -->
             <h3>扫描摘要</h3>
            <p><strong>扫描时间:</strong> {{.Timestamp}}</p>
            <p><strong>共扫描文件:</strong> {{len .ScannedFiles}}</p>
            <p><strong>发现漏洞的依赖项:</strong> {{len .Results}} 个</p>
            <p><strong>总计依赖漏洞 (SCA):</strong> {{ TotalVulns .Results }} 个</p>
            <p><strong>代码中的潜在利用点 (VCSA):</strong> {{len .VCSAFindings}} 个</p>
        </div>
        <!-- ... (VCSA 和 SCA 的结果展示不变) ... -->
         {{if .VCSAFindings}}
<h2><span style="color: #c0392b;">🔴</span> 代码安全审计 (VCSA) 结果</h2>
<p>以下是在代码中发现的、与依赖漏洞相关的潜在利用点，请优先关注：</p>
{{range .VCSAFindings}}
<div class="card">
    <div class="card-header vcsa-header">
        <span>{{.FilePath}}:{{.Line}}</span>
		<span class="tag tag-cwe">{{.RuleID}}</span>
    </div>
    <div class="card-body">
        <p><strong>描述:</strong> {{.Message}}</p>
        <p><strong>代码片段:</strong></p>
        <pre><code>{{ TrimSpace .CodeSnippet }}</code></pre>
    </div>
</div>
{{end}}
{{end}}

<h2><span style="color: #f39c12;">🟡</span> 依赖安全扫描 (SCA) 结果</h2>
{{range .Results}}
<div class="card">
    <div class="card-header vuln-header">
        <span>{{.Dependency.Name}} @ {{.Dependency.Version}}</span>
		<span class="tag tag-ecosystem">{{.Dependency.Ecosystem}}</span>
    </div>
    <div class="card-body">
        <p><strong>发现于:</strong> <code>{{.Dependency.File}}</code></p>
        <h4>发现 {{len .Vulnerabilities}} 个漏洞:</h4>
        {{range .Vulnerabilities}}
        <div class="vuln-item">
            <p><span class="vuln-id">{{.ID}}</span> {{range .Aliases}}({{.}}) {{end}}</p>
            <p><strong>摘要:</strong> {{if .Summary}}{{.Summary}}{{else}}(无可用摘要){{end}}</p>
			{{if .CWEs}}<p><strong>漏洞类型 (CWE):</strong> {{range .CWEs}}<span class="tag tag-cwe">{{.}}</span> {{end}}</p>{{end}}
        </div>
        {{end}}
    </div>
</div>
{{else}}
<div class="summary" style="background-color: #d4edda;">
    <h2><span style="color: #27ae60;">✅</span> 恭喜！未在依赖项中发现任何已知漏洞。</h2>
</div>
{{end}}
    </div>

    <script>
        function exportPDF() {
            const { jsPDF } = window.jspdf;
            const reportContent = document.getElementById('report-content');
            const exportButton = document.querySelector('.export-btn');
            
            // 导出前先隐藏按钮，避免打印到PDF里
            exportButton.style.display = 'none';

            html2canvas(reportContent, {
                scale: 2, // 提高截图清晰度
                useCORS: true
            }).then(canvas => {
                const imgData = canvas.toDataURL('image/png');
                const pdf = new jsPDF('p', 'mm', 'a4');
                const pdfWidth = pdf.internal.pageSize.getWidth();
                const pdfHeight = pdf.internal.pageSize.getHeight();
                const imgWidth = canvas.width;
                const imgHeight = canvas.height;
                const ratio = Math.min(pdfWidth / imgWidth, pdfHeight / imgHeight);
                const imgX = (pdfWidth - imgWidth * ratio) / 2;
                
                let position = 0;
                const pageHeight = pdf.internal.pageSize.height;
                const canvasHeight = imgHeight * ratio;
                let heightLeft = canvasHeight;

                pdf.addImage(imgData, 'PNG', imgX, position, imgWidth * ratio, imgHeight * ratio);
                heightLeft -= pageHeight;

                while (heightLeft > 0) {
                    position = heightLeft - canvasHeight;
                    pdf.addPage();
                    pdf.addImage(imgData, 'PNG', imgX, position, imgWidth * ratio, imgHeight * ratio);
                    heightLeft -= pageHeight;
                }
                
                pdf.save('argus-report.pdf');
                
                // 导出后再把按钮显示回来
                exportButton.style.display = 'block';
            });
        }
    </script>
</body>
</html>
`
