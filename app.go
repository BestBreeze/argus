// app.go
//go:build !cli

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"argus/analyzer"
	"argus/parser"
	"argus/preprocessor"
	"argus/reporter"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// SelectProject a method that opens a file selection dialog.
// It's callable from the frontend.
func (a *App) SelectProject() (string, error) {
	// 使用Wails的运行时对话框API来选择文件夹
	selection, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "请选择项目文件夹",
	})
	if err != nil {
		return "", err
	}
	return selection, nil
}

// ScanProject is the main scanning function callable from the frontend.
// It takes a path and returns the path to the generated report.
func (a *App) ScanProject(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("未提供项目路径")
	}

	// --- 我们将main_cli.go的核心逻辑移植到这里 ---

	// 向前端发送日志事件，告知扫描开始
	runtime.EventsEmit(a.ctx, "log", "扫描引擎启动... 目标: "+path)

	// 阶段0: 输入预处理
	scanPath, cleanup, err := preprocessor.ProcessInput(path)
	if err != nil {
		runtime.EventsEmit(a.ctx, "log", "错误: 输入处理失败: "+err.Error())
		return "", err
	}
	defer cleanup()
	runtime.EventsEmit(a.ctx, "log", "输入预处理完成，扫描路径: "+scanPath)

	// 阶段1: 解析
	runtime.EventsEmit(a.ctx, "log", "阶段1: 正在解析依赖文件...")
	var allDependencies []parser.Dependency
	var foundDepFiles []string
	filepath.WalkDir(scanPath, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			pr := parser.GetParser(p)
			if pr != nil {
				runtime.EventsEmit(a.ctx, "log", fmt.Sprintf("  [+] 发现依赖文件: %s", p))
				foundDepFiles = append(foundDepFiles, p)
				deps, err := pr.Parse(p)
				if err != nil {
					runtime.EventsEmit(a.ctx, "log", fmt.Sprintf("    [!] 解析失败: %v", err))
				} else {
					allDependencies = append(allDependencies, deps...)
				}
			}
		}
		return nil
	})
	runtime.EventsEmit(a.ctx, "log", fmt.Sprintf("解析完成, 找到 %d 个依赖项。", len(allDependencies)))

	// 阶段2 & 2.5: 分析
	runtime.EventsEmit(a.ctx, "log", "阶段2: 正在分析漏洞 (SCA + VCSA)...")
	report := analyzer.Analyze(allDependencies, scanPath)
	report.ScannedFiles = foundDepFiles

	// 阶段3: 报告
	runtime.EventsEmit(a.ctx, "log", "阶段3: 正在生成HTML报告...")
	// 将报告生成在用户主目录的 .argus/reports 文件夹下，避免权限问题
	homeDir, _ := os.UserHomeDir()
	reportDir := filepath.Join(homeDir, ".argus", "reports")
	os.MkdirAll(reportDir, os.ModePerm)
	reportPath := filepath.Join(reportDir, fmt.Sprintf("argus_report_%d.html", time.Now().Unix()))

	err = reporter.GenerateHTMLReport(report, reportPath)
	if err != nil {
		runtime.EventsEmit(a.ctx, "log", "错误: 生成报告失败: "+err.Error())
		return "", err
	}

	runtime.EventsEmit(a.ctx, "log", fmt.Sprintf("扫描完成！报告已保存至: %s", reportPath))
	return reportPath, nil
}

// OpenReportInBrowser opens the generated HTML report in the user's default browser.
func (a *App) OpenReportInBrowser(reportPath string) {
	if reportPath == "" {
		return
	}
	runtime.BrowserOpenURL(a.ctx, reportPath)
}
