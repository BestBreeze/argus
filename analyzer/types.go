// analyzer/types.go
package analyzer

import (
	"argus/api"
	"argus/parser"
	"argus/vcsa" // 导入vcsa包
)

// Result 是单个依赖项的完整扫描结果
type Result struct {
	Dependency      parser.Dependency
	Vulnerabilities []api.Vulnerability
}

// Report 是整个项目的最终扫描报告
type Report struct {
	ScannedFiles []string       // 本次扫描了哪些文件
	Results      []Result       // 所有有漏洞的依赖项的结果列表
	VCSAFindings []vcsa.Finding // 所有VCSA发现的列表
	Timestamp    string         // 扫描完成时的时间戳
}
