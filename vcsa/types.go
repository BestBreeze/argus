package vcsa

type Rule struct {
	Name      string   `json:"name"`
	Languages []string `json:"languages"`
	Keywords  []string `json:"keywords"`
	Message   string   `json:"message"`
}
type RuleSet map[string]Rule
type Finding struct {
	RuleID      string
	FilePath    string
	Line        int
	CodeSnippet string
	Message     string
}
