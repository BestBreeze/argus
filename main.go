// main.go
package main

import (
	"fmt"
	"log"
	"os"

	"argus/analyzer"
	"argus/parser"
	"argus/reporter"
)

func main() {
	fmt.Println("百眼巨人(Argus)安全引擎启动...")

	// --- 阶段1: 解析 ---
	targetFiles := []string{"requirements.txt", "pom.xml"}
	var allDependencies []parser.Dependency
	var foundFiles []string

	for _, file := range targetFiles {
		// 检查文件是否存在
		if _, err := os.Stat(file); os.IsNotExist(err) {
			continue
		}

		p := parser.GetParser(file)
		if p == nil {
			continue
		}

		foundFiles = append(foundFiles, file)
		deps, err := p.Parse(file)
		if err != nil {
			log.Printf("警告: 解析文件 '%s' 失败: %v", file, err)
			continue
		}
		allDependencies = append(allDependencies, deps...)
	}
	fmt.Printf("解析完成, 共找到 %d 个依赖项。\n", len(allDependencies))

	// --- 阶段2: 分析 ---
	fmt.Println("开始并发扫描漏洞...")
	report := analyzer.AnalyzeDependencies(allDependencies)
	report.ScannedFiles = foundFiles // 补全报告中的文件列表
	fmt.Println("漏洞扫描完成。")

	// --- 阶段3: 报告 ---
	reportPath := "argus_report.html"
	fmt.Printf("正在生成HTML报告: %s\n", reportPath)
	err := reporter.GenerateHTMLReport(report, reportPath)
	if err != nil {
		log.Fatalf("生成报告失败: %v", err)
	}

	fmt.Println("报告生成成功！")
}
