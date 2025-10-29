// main.go (第八周最终版)
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"argus/analyzer"
	"argus/parser"
	"argus/preprocessor"
	"argus/reporter"
)

func main() {
	// 定义命令行参数
	input := flag.String("path", ".", "要扫描的项目文件夹或压缩包路径")
	output := flag.String("output", "argus_report.html", "输出报告的文件名")
	flag.Parse()

	fmt.Printf("百眼巨人(Argus)安全引擎启动... 目标: %s\n", *input)

	// --- 阶段0: 输入预处理 ---
	scanPath, cleanup, err := preprocessor.ProcessInput(*input)
	if err != nil {
		log.Fatalf("输入处理失败: %v", err)
	}
	defer cleanup() // 确保程序退出时清理临时文件

	// --- 阶段1: 解析依赖文件 (SCA准备) ---
	fmt.Println("\n--- 阶段1: 解析依赖文件 ---")
	var allDependencies []parser.Dependency
	var foundDepFiles []string

	// 遍历扫描目录，寻找所有支持的依赖文件
	filepath.WalkDir(scanPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			p := parser.GetParser(path)
			if p != nil {
				fmt.Printf("  [+] 发现依赖文件: %s\n", path)
				foundDepFiles = append(foundDepFiles, path)
				deps, err := p.Parse(path)
				if err != nil {
					log.Printf("    [!] 解析失败: %v\n", err)
				} else {
					allDependencies = append(allDependencies, deps...)
				}
			}
		}
		return nil
	})
	fmt.Printf("解析完成, 在 %d 个文件中找到 %d 个依赖项。\n", len(foundDepFiles), len(allDependencies))

	// --- 阶段2 & 2.5: 分析 (SCA + VCSA联动) ---
	fmt.Println("\n--- 阶段2: 分析依赖项漏洞与代码关联 ---")
	report := analyzer.Analyze(allDependencies, scanPath)
	report.ScannedFiles = foundDepFiles

	// --- 阶段3: 报告 ---
	fmt.Printf("\n--- 阶段3: 生成报告 ---\n")
	fmt.Printf("正在生成HTML报告: %s\n", *output)
	err = reporter.GenerateHTMLReport(report, *output)
	if err != nil {
		log.Fatalf("生成报告失败: %v", err)
	}

	fmt.Printf("\n扫描完成！报告已保存至 %s\n", *output)
}
