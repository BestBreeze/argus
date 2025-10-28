// analyzer/types.go
package analyzer

import (
	"argus/api"
	"argus/parser"
)

// Result 是单个依赖项的完整扫描结果
type Result struct {
	Dependency      parser.Dependency   // 这个依赖项的原始信息
	Vulnerabilities []api.Vulnerability // 在这个依赖项上发现的所有漏洞
}

// Report 是整个项目的最终扫描报告
type Report struct {
	ScannedFiles []string // 本次扫描了哪些文件
	Results      []Result // 所有有漏洞的依赖项的结果列表
	Timestamp    string   // 扫描完成时的时间戳
}
