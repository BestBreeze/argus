// parser/dispatcher.go
package parser

import (
	"path/filepath"
)

// GetParser 根据文件名返回对应的解析器实例
// 注意它的返回值是 Parser 接口类型，而不是某个具体的解析器类型
func GetParser(filePath string) Parser {
	filename := filepath.Base(filePath) // 获取文件名，如 "pom.xml"

	switch filename {
	case "requirements.txt":
		return &RequirementsParser{}
	case "pom.xml":
		return &PomParser{}
	// 未来支持新语言，只需在这里增加一个 case
	default:
		return nil // 如果是不支持的文件类型，返回 nil
	}
}
