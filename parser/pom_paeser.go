// parser/pom_parser.go
package parser

import (
	"encoding/xml"
	"os"
)

// PomParser 实现了 Parser 接口，用于解析 pom.xml 文件
type PomParser struct{}

// PomProject 结构体用于映射 pom.xml 的顶层结构
type PomProject struct {
	XMLName      xml.Name        `xml:"project"`
	Dependencies []PomDependency `xml:"dependencies>dependency"` // 路径选择语法
}

// PomDependency 结构体用于映射 <dependency> 标签
type PomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// Parse 方法负责解析 pom.xml
func (p *PomParser) Parse(filePath string) ([]Dependency, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var project PomProject
	// 使用 xml.NewDecoder 来解析XML流
	decoder := xml.NewDecoder(file)
	if err := decoder.Decode(&project); err != nil {
		return nil, err
	}

	var dependencies []Dependency
	for _, d := range project.Dependencies {
		// 对于版本号为空的依赖，我们暂时忽略（在实际项目中可能需要处理变量）
		if d.Version == "" {
			continue
		}

		dependencies = append(dependencies, Dependency{
			// Maven 的包名通常是 "groupId:artifactId"
			Name:      d.GroupID + ":" + d.ArtifactID,
			Version:   d.Version,
			Ecosystem: "Maven",
			File:      filePath,
		})
	}

	return dependencies, nil
}
