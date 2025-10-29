// api/osv.go
package api

import "time"

// OSVResponse 对应从OSV API返回的完整JSON结构
type OSVResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

// Vulnerability 对应单个漏洞的详细信息
type Vulnerability struct {
	ID               string                 `json:"id"`
	Summary          string                 `json:"summary"`
	Details          string                 `json:"details"`
	Aliases          []string               `json:"aliases"`
	Modified         time.Time              `json:"modified"`
	Published        time.Time              `json:"published"`
	Affected         []Affected             `json:"affected"`
	Severity         []Severity             `json:"severity"`
	References       []Reference            `json:"references"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
	CWEs             []string               `json:"-"` // 必须换行
}

// Affected 描述受影响的包和版本范围
type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []Range  `json:"ranges"`
	Versions []string `json:"versions"`
}

// Package 描述一个软件包
type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// Range 描述版本范围
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event 描述版本范围的事件，如 "introduced" 或 "fixed"
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// Severity 描述漏洞的严重性
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Reference 描述相关的参考链接
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}
