// analyzer/analyzer.go
package analyzer

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync" // 导入并发控制包
	"time"

	"argus/api"
	"argus/parser"
)

// OSVQuery 结构体用于构建对OSV API的请求
type OSVQuery struct {
	Version string      `json:"version"`
	Package api.Package `json:"package"`
}

// AnalyzeDependencies 接收依赖项列表，返回一份完整的报告
func AnalyzeDependencies(dependencies []parser.Dependency) Report {

	// --- 并发扫描优化 ---
	// 为了提高效率，我们将并发地扫描所有依赖项
	var wg sync.WaitGroup                               // WaitGroup 用于等待所有goroutine完成
	resultsChan := make(chan Result, len(dependencies)) // Channel 用于从goroutine安全地接收结果

	for _, dep := range dependencies {
		wg.Add(1) // 计数器+1
		go func(d parser.Dependency) {
			defer wg.Done() // 函数结束时计数器-1

			// 为每个依赖项单独执行扫描
			query := OSVQuery{
				Version: d.Version,
				Package: api.Package{Name: d.Name, Ecosystem: d.Ecosystem},
			}

			// ... (这里的请求和解析逻辑与之前类似) ...
			queryJSON, _ := json.Marshal(query)
			resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(queryJSON))
			if err != nil {
				log.Printf("警告: 为 %s 请求API失败: %v", d.Name, err)
				return
			}
			defer resp.Body.Close()

			var osvResp api.OSVResponse
			if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
				// 忽略空的响应体错误
			}

			// 如果发现了漏洞，就将结果发送到channel中
			if len(osvResp.Vulns) > 0 {
				resultsChan <- Result{
					Dependency:      d,
					Vulnerabilities: osvResp.Vulns,
				}
			}
		}(dep) // 将dep作为参数传入goroutine，避免闭包问题
	}

	wg.Wait()          // 阻塞，直到所有goroutine都调用了wg.Done()
	close(resultsChan) // 关闭channel
	// --- 并发扫描结束 ---

	// 整理最终报告
	finalReport := Report{
		ScannedFiles: []string{}, // 我们需要在主程序中填充这个
		Results:      []Result{},
		Timestamp:    time.Now().Format(time.RFC1123),
	}

	// 从channel中收集所有结果
	for res := range resultsChan {
		finalReport.Results = append(finalReport.Results, res)
	}

	return finalReport
}
