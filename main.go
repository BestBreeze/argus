// main.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	// 导入我们自己创建的api包
	// "argus" 是我们在 go.mod 文件中定义的模块名
	"argus/api"
)

// OSVQuery 和 Package 结构体可以移到 api/osv.go 中，或者保留在这里用于查询
// 为了清晰，我们暂时保留在这里
type OSVQuery struct {
	Version string       `json:"version"`
	Package api.Package `json:"package"` // 复用 api 包中的 Package 结构体
}

func main() {
	fmt.Println("百眼巨人(Argus)安全引擎启动...")

	query := OSVQuery{
		Version: "2.25.0",
		Package: api.Package{ // 使用 api.Package
			Name:      "requests",
			Ecosystem: "PyPI",
		},
	}

	queryJSON, err := json.Marshal(query)
	if err != nil {
		log.Fatalf("无法编码JSON: %v", err)
	}

	resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(queryJSON))
	if err != nil {
		log.Fatalf("HTTP请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("无法读取响应: %v", err)
	}

	// --- 这里是本周的核心改动 ---
	// 1. 创建一个 OSVResponse 变量来存放解析后的数据
	var osvResp api.OSVResponse

	// 2. 使用 json.Unmarshal 将原始的JSON数据(body)解析到 osvResp 变量中
	if err := json.Unmarshal(body, &osvResp); err != nil {
		// 如果JSON是空的(比如没有漏洞)，Unmarshal不会报错，但我们的osvResp.Vulns会是空的
		// 我们需要处理真正的解析错误
        if len(body) > 0 { // 只有在响应体不为空时，才认为是解析错误
            log.Fatalf("无法解析JSON响应: %v", err)
        }
	}

	// 3. 检查并打印解析后的结构化数据
	if len(osvResp.Vulns) > 0 {
		fmt.Printf("\n--- 成功解析出 %d 个漏洞信息 ---\n", len(osvResp.Vulns))

		// 遍历并打印每个漏洞的关键信息
		for i, vuln := range osvResp.Vulns {
			fmt.Printf("\n漏洞 #%d:\n", i+1)
			fmt.Printf("  ID: %s\n", vuln.ID)
			fmt.Printf("  摘要: %s\n", vuln.Summary)

			// 提取修复版本
			fixedVersion := "N/A"
			if len(vuln.Affected) > 0 && len(vuln.Affected[0].Ranges) > 0 {
				for _, event := range vuln.Affected[0].Ranges[0].Events {
					if event.Fixed != "" {
						fixedVersion = event.Fixed
						break
					}
				}
			}
			fmt.Printf("  修复版本: %s\n", fixedVersion)
		}
	} else {
		fmt.Println("\n--- 未发现任何漏洞 ---")
	}
}