package report

import (
	"embed"
	"html/template"
	"io"
)

//go:embed templates/report.html.tmpl
var templates embed.FS

var htmlTmpl = template.Must(template.ParseFS(templates, "templates/report.html.tmpl"))

// HTML writes a single self-contained report page. html/template escapes
// all finding content, including code snippets.
func HTML(w io.Writer, d Data) error {
	return htmlTmpl.Execute(w, d)
}
