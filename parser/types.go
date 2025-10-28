// parser/types.go
package parser

// Dependency 代表一个解析出的软件依赖项
type Dependency struct {
	Name      string // 依赖项的名称, e.g., "requests" or "org.apache.logging.log4j:log4j-core"
	Version   string // 依赖项的版本, e.g., "2.25.0"
	Ecosystem string // 所属的生态系统, e.g., "PyPI", "Maven"
	File      string // 依赖项被发现于哪个文件
}

// Parser 是一个接口，定义了所有语言解析器都必须实现的行为
// 任何实现了 Parse(filePath string) ([]Dependency, error) 方法的类型，
// 都自动被认为是 Parser 类型。
type Parser interface {
	Parse(filePath string) ([]Dependency, error)
}
