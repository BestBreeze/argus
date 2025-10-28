// vcsa/types.go
package vcsa

// Rule 定义了知识库中单条规则的结构
type Rule struct {
	Name       string   `json:"name"`
	Languages  []string `json:"languages"`
	Severity   string   `json:"severity"`
	Mode       string   `json:"mode"`
	Sources    []string `json:"pattern-sources"`
	Sinks      []string `json:"pattern-sinks"`
	Sanitizers []string `json:"pattern-sanitizers,omitempty"`
	Message    string   `json:"message"`
}

// RuleSet 是整个知识库的结构
type RuleSet map[string]Rule

// Finding 代表 VCSA 发现的一个具体的代码问题
type Finding struct {
	RuleID      string `json:"rule_id"`
	FilePath    string `json:"path"`
	Line        int    `json:"start_line"` // 简化处理，只取起始行
	Column      int    `json:"start_col"`
	Message     string `json:"message"`
	CodeSnippet string `json:"code_snippet"` // 我们稍后会尝试提取
}
