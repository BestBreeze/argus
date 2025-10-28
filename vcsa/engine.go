// vcsa/engine.go
package vcsa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"gopkg.in/yaml.v3"
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

// SemgrepPattern 是一个辅助结构，用于表示 {pattern: "..."}
type SemgrepPattern struct {
	Pattern string `yaml:"pattern"`
}

// SemgrepRule 现在使用 SemgrepPattern 列表
type SemgrepRule struct {
	ID                string           `yaml:"id"`
	Message           string           `yaml:"message"`
	Severity          string           `yaml:"severity"`
	Languages         []string         `yaml:"languages"`
	Mode              string           `yaml:"mode"`
	PatternSources    []SemgrepPattern `yaml:"pattern-sources"`
	PatternSinks      []SemgrepPattern `yaml:"pattern-sinks"`
	PatternSanitizers []SemgrepPattern `yaml:"pattern-sanitizers,omitempty"`
}
type SemgrepConfig struct {
	Rules []SemgrepRule `yaml:"rules"`
}

// generateSemgrepConfig 根据 CWE 编号动态生成 Semgrep 配置文件
func (e *Engine) generateSemgrepConfig(cweIDs []string, outputPath string) error {
	var config SemgrepConfig
	for _, cwe := range cweIDs {
		if rule, ok := e.Rules[cwe]; ok {

			// 将字符串列表转换为 SemgrepPattern 列表
			var sources []SemgrepPattern
			for _, s := range rule.Sources {
				sources = append(sources, SemgrepPattern{Pattern: s})
			}

			var sinks []SemgrepPattern
			for _, s := range rule.Sinks {
				sinks = append(sinks, SemgrepPattern{Pattern: s})
			}

			var sanitizers []SemgrepPattern
			for _, s := range rule.Sanitizers {
				sanitizers = append(sanitizers, SemgrepPattern{Pattern: s})
			}

			config.Rules = append(config.Rules, SemgrepRule{
				ID:                cwe,
				Message:           rule.Message,
				Severity:          rule.Severity,
				Languages:         rule.Languages,
				Mode:              rule.Mode,
				PatternSources:    sources,
				PatternSinks:      sinks,
				PatternSanitizers: sanitizers,
			})
		}
	}

	if len(config.Rules) == 0 {
		return fmt.Errorf("no matching rules found for CWEs: %v", cweIDs)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)
	return encoder.Encode(config)
}

// Scan 通过调用本地安装的 semgrep 执行扫描
func (e *Engine) Scan(targetPath string, cweIDs []string) ([]Finding, error) {
	// 1. 生成临时的规则文件
	tempRuleFile, err := os.CreateTemp("", "argus_semgrep_rules-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp rule file: %v", err)
	}
	tempRuleFilePath := tempRuleFile.Name()
	tempRuleFile.Close()

	if err := e.generateSemgrepConfig(cweIDs, tempRuleFilePath); err != nil {
		// 如果没有找到对应规则，这不是一个致命错误，只是本次VCSA无需执行
		return nil, nil
	}
	defer os.Remove(tempRuleFilePath)

	// 2. 构建本地 semgrep 命令
	cmd := exec.Command("semgrep",
		"scan",
		"--config", tempRuleFilePath,
		"--json",
		"--quiet",
		targetPath, // 直接扫描本地路径
	)

	// 3. 执行命令并捕获输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		var semgrepResp struct {
			Results []interface{} `json:"results"`
		}
		if json.Unmarshal(output, &semgrepResp) == nil && len(semgrepResp.Results) > 0 {
			// 即使有退出码，但只要能解析出JSON且有结果，我们就认为它是成功执行了
		} else {
			return nil, fmt.Errorf("semgrep execution failed: %v. Output: %s", err, string(output))
		}
	}

	// 4. 解析 Semgrep 的 JSON 输出
	// 4. 清洗输出，只保留有效的JSON部分
	jsonStartIndex := bytes.IndexRune(output, '{')
	if jsonStartIndex == -1 {
		return nil, fmt.Errorf("semgrep did not produce valid JSON output. Raw output: %s", string(output))
	}
	jsonOutput := output[jsonStartIndex:]

	// 5. 解析清洗后的JSON
	var semgrepResp struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
				Col  int `json:"col"`
			} `json:"start"`
			Extra struct {
				Message string `json:"message"`
				Lines   string `json:"lines"`
			} `json:"extra"`
		} `json:"results"`
	}

	if err := json.Unmarshal(jsonOutput, &semgrepResp); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep's JSON output: %v. Cleaned output: %s", err, string(jsonOutput))
	}

	// 5. 转换为我们将使用的 Finding 结构
	var findings []Finding
	for _, res := range semgrepResp.Results {
		findings = append(findings, Finding{
			RuleID:      res.CheckID,
			FilePath:    res.Path,
			Line:        res.Start.Line,
			Column:      res.Start.Col,
			Message:     res.Extra.Message,
			CodeSnippet: res.Extra.Lines,
		})
	}

	return findings, nil
}
