// analyzer/analyzer.go
package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"argus/api"
	"argus/parser"
	"argus/vcsa"
)

// OSVQuery 结构体用于构建对OSV API的请求
type OSVQuery struct {
	Version string      `json:"version"`
	Package api.Package `json:"package"`
}

// Analyze 接收依赖项列表和扫描路径，返回一份完整的报告
func Analyze(dependencies []parser.Dependency, scanPath string) Report {
	// --- 阶段1: 并发执行SCA扫描 ---
	var wg sync.WaitGroup
	resultsChan := make(chan Result, len(dependencies))

	for _, dep := range dependencies {
		wg.Add(1)
		go func(d parser.Dependency) {
			defer wg.Done()

			query := OSVQuery{
				Version: d.Version,
				Package: api.Package{Name: d.Name, Ecosystem: d.Ecosystem},
			}

			queryJSON, _ := json.Marshal(query)
			resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(queryJSON))
			if err != nil {
				log.Printf("警告: 为 %s 请求API失败: %v", d.Name, err)
				return
			}
			defer resp.Body.Close()

			var osvResp api.OSVResponse
			if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
				// 忽略空响应体导致的EOF错误
			}

			if len(osvResp.Vulns) > 0 {
				// 提取CWE编号
				for i := range osvResp.Vulns {
					vuln := &osvResp.Vulns[i] // 使用指针，避免复制
					if dbSpecific, ok := vuln.DatabaseSpecific["cwe_ids"].([]interface{}); ok {
						for _, cwe := range dbSpecific {
							if cweStr, ok := cwe.(string); ok {
								vuln.CWEs = append(vuln.CWEs, cweStr)
							}
						}
					}
				}
				resultsChan <- Result{
					Dependency:      d,
					Vulnerabilities: osvResp.Vulns,
				}
			}
		}(dep)
	}

	wg.Wait()
	close(resultsChan)

	// --- 阶段2: 收集SCA结果并准备VCSA ---
	scaResults := []Result{}
	allCWEs := make(map[string]bool)

	// --- 核心修改在这里 ---
	for res := range resultsChan {
		scaResults = append(scaResults, res)
		// 遍历Result中的每一个Vulnerability来收集CWE
		for _, vuln := range res.Vulnerabilities {
			for _, cwe := range vuln.CWEs {
				allCWEs[cwe] = true
			}
		}
	}
	// --- 修改结束 ---

	// --- 阶段3: 如果有必要，触发VCSA扫描 ---
	var vcsaFindings []vcsa.Finding
	if len(allCWEs) > 0 {
		fmt.Println("\n--- 阶段2.5: 触发漏洞关联静态分析 (VCSA) ---")

		var cweList []string
		for cwe := range allCWEs {
			cweList = append(cweList, cwe)
		}
		fmt.Printf("根据SCA结果, 将针对以下漏洞类型进行代码审计: %v\n", cweList)

		vcsaEngine, err := vcsa.NewEngine("rules/vcsa_rules.json")
		if err != nil {
			log.Printf("警告: VCSA引擎初始化失败: %v", err)
		} else {
			findings, err := vcsaEngine.Scan(scanPath, cweList)
			if err != nil {
				log.Printf("警告: VCSA扫描执行失败: %v", err)
			} else if len(findings) > 0 {
				vcsaFindings = findings
				fmt.Printf("VCSA扫描完成, 发现 %d 个潜在利用点。\n", len(vcsaFindings))
			} else {
				fmt.Println("VCSA扫描完成, 未在代码中发现明确的利用路径。")
			}
		}
	}

	// --- 阶段4: 组装最终报告 ---
	finalReport := Report{
		Results:      scaResults,
		VCSAFindings: vcsaFindings,
		Timestamp:    time.Now().Format(time.RFC1123),
	}

	return finalReport
}
