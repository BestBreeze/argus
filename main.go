// main.go
package main

import (
	"flag" // 导入 flag 包
	"fmt"
	"log"
	"os"

	"argus/analyzer"
	"argus/parser"
	"argus/reporter"
	"argus/vcsa" // 导入 vcsa 包
)

func main() {
	// --- 新增：定义命令行参数 ---
	// 定义一个名为 "-mode" 的参数，默认值为 "sca"
	// 用法: go run main.go -mode=vcsa
	mode := flag.String("mode", "sca", "扫描模式: 'sca' (依赖扫描) 或 'vcsa' (漏洞关联静态分析)")
	// 定义一个 -cwe 参数，用于 vcsa 模式
	cwe := flag.String("cwe", "CWE-502", "在 VCSA 模式下要扫描的 CWE 编号")

	// 解析用户传入的命令行参数
	flag.Parse()

	fmt.Printf("百眼巨人(Argus)安全引擎启动... [模式: %s]\n", *mode)

	// --- 根据模式选择执行不同的逻辑 ---
	if *mode == "sca" {
		runSCAScan()
	} else if *mode == "vcsa" {
		runVCSAScan(*cwe)
	} else {
		log.Fatalf("错误: 未知的模式 '%s'. 请使用 'sca' 或 'vcsa'.", *mode)
	}
}

// runSCAScan 函数包含了我们之前所有的SCA逻辑
func runSCAScan() {
	fmt.Println("--- 阶段1: 解析 ---")
	targetFiles := []string{"requirements.txt", "pom.xml"}
	var allDependencies []parser.Dependency
	var foundFiles []string

	for _, file := range targetFiles {
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

	fmt.Println("--- 阶段2: 分析 ---")
	fmt.Println("开始并发扫描漏洞...")
	report := analyzer.AnalyzeDependencies(allDependencies)
	report.ScannedFiles = foundFiles
	fmt.Println("漏洞扫描完成。")

	fmt.Println("--- 阶段3: 报告 ---")
	reportPath := "argus_report.html"
	fmt.Printf("正在生成HTML报告: %s\n", reportPath)
	err := reporter.GenerateHTMLReport(report, reportPath)
	if err != nil {
		log.Fatalf("生成报告失败: %v", err)
	}

	fmt.Println("报告生成成功！")
}

// runVCSAScan 函数用于执行我们本周开发的VCSA逻辑
func runVCSAScan(cweID string) {
	// 1. 初始化引擎
	engine, err := vcsa.NewEngine("rules/vcsa_rules.json")
	if err != nil {
		log.Fatalf("VCSA引擎初始化失败: %v", err)
	}

	// 2. 定义要扫描的目标目录（就是当前目录）
	targetDir, _ := os.Getwd()

	// 3. 定义要扫描的漏洞类型 (从参数传入)
	cwes := []string{cweID}

	fmt.Printf("开始在 %s 中进行VCSA扫描 [CWEs: %v] ...\n", targetDir, cwes)
	findings, err := engine.Scan(targetDir, cwes)
	if err != nil {
		log.Fatalf("VCSA扫描失败: %v", err)
	}

	fmt.Printf("扫描完成，发现 %d 个潜在利用点:\n", len(findings))
	if len(findings) > 0 {
		for _, f := range findings {
			fmt.Printf("\n========================================\n")
			fmt.Printf("规则ID: %s\n", f.RuleID)
			fmt.Printf("文件: %s:%d\n", f.FilePath, f.Line)
			fmt.Printf("描述: %s\n", f.Message)
			fmt.Printf("代码片段:\n%s\n", f.CodeSnippet)
			fmt.Printf("========================================\n")
		}
	}
}
