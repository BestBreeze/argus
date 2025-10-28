// parser/requirements_parser.go
package parser

import (
	"bufio"
	"os"
	"strings"
)

// RequirementsParser 实现了 Parser 接口，用于解析 requirements.txt 文件
type RequirementsParser struct{}

// Parse 是 RequirementsParser 的方法，负责具体的解析逻辑
// 这个方法签名完全符合我们定义的 Parser 接口
func (p *RequirementsParser) Parse(filePath string) ([]Dependency, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var dependencies []Dependency
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var name, version string
		delimiters := []string{"==", ">=", "<=", ">", "<", "~="}
		isFound := false

		for _, d := range delimiters {
			if strings.Contains(line, d) {
				parts := strings.SplitN(line, d, 2)
				name = strings.TrimSpace(parts[0])
				version = strings.TrimSpace(parts[1])
				isFound = true
				break
			}
		}

		if !isFound {
			continue
		}

		if name != "" && version != "" {
			dependencies = append(dependencies, Dependency{
				Name:      name,
				Version:   version,
				Ecosystem: "PyPI",
				File:      filePath,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return dependencies, nil
}
