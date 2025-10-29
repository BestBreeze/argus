// vcsa/engine.go
package vcsa

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Engine 是 VCSA 引擎的主体
type Engine struct {
	Rules RuleSet
}

// NewEngine 初始化引擎并加载规则库
func NewEngine(rulesPath string) (*Engine, error) {
	file, err := os.Open(rulesPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules RuleSet
	if err := json.NewDecoder(file).Decode(&rules); err != nil {
		return nil, err
	}

	return &Engine{Rules: rules}, nil
}

// normalizeString 辅助函数: 移除所有空格并转为小写，用于健壮的比较
func normalizeString(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, " ", ""))
}

// Scan [终极健 nổi版]
// 使用标准化的字符串比较来排除所有不可见的字符和格式问题
func (e *Engine) Scan(targetPath string, cweIDs []string) ([]Finding, error) {
	var findings []Finding
	activeRules := make(map[string]Rule)
	activeLangs := make(map[string]bool)

	for _, cwe := range cweIDs {
		if rule, ok := e.Rules[cwe]; ok {
			activeRules[cwe] = rule
			for _, lang := range rule.Languages {
				activeLangs[lang] = true
			}
		}
	}
	if len(activeRules) == 0 {
		return findings, nil
	}

	// 恢复使用 WalkDir，因为我们已确认问题在于字符串比较
	err := filepath.WalkDir(targetPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		lang := getLanguageByExtension(path)
		if !activeLangs[lang] {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNumber := 1
		for scanner.Scan() {
			originalLine := scanner.Text()
			// 核心修改：对代码行和关键词进行“标准化”处理
			normalizedLine := normalizeString(originalLine)

			for cwe, rule := range activeRules {
				if !isLangInRule(lang, rule.Languages) {
					continue
				}

				for _, keyword := range rule.Keywords {
					// 对关键词也进行标准化
					normalizedKeyword := normalizeString(keyword)

					// 使用标准化后的字符串进行最可靠的包含检查
					if strings.Contains(normalizedLine, normalizedKeyword) {
						fmt.Printf("[VCSA调试] 找到匹配! 文件: %s, 行号: %d, 关键词: '%s'\n", path, lineNumber, keyword)
						findings = append(findings, Finding{
							RuleID:      cwe,
							FilePath:    path,
							Line:        lineNumber,
							CodeSnippet: strings.TrimSpace(originalLine), // 报告的依然是原始代码
							Message:     rule.Message,
						})
						// 找到一个匹配后就可以跳出内层循环
						break
					}
				}
			}
			lineNumber++
		}
		return nil
	})

	return findings, err
}

// getLanguageByExtension 是一个辅助函数，根据文件后缀名判断语言
func getLanguageByExtension(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".java":
		return "java"
	case ".py":
		return "python"
	case ".go":
		return "go"
	// 未来可扩展
	default:
		return "unknown"
	}
}

// isLangInRule 检查语言是否在规则的语言列表中
func isLangInRule(lang string, ruleLangs []string) bool {
	for _, l := range ruleLangs {
		if l == lang {
			return true
		}
	}
	return false
}
