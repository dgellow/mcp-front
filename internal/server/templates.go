package server

import (
	_ "embed"
	"html/template"
)

//go:embed templates/tokens.html
var tokenPageTemplateHTML string

//go:embed templates/admin.html
var adminPageTemplateHTML string

var tokenPageTemplate = template.Must(template.New("tokens").Parse(tokenPageTemplateHTML))
var adminPageTemplate = template.Must(template.New("admin").Parse(adminPageTemplateHTML))

// TokenPageData represents the data for the token management page
type TokenPageData struct {
	UserEmail   string
	Services    []ServiceTokenData
	CSRFToken   string
	Message     string
	MessageType string // "success" or "error"
}

// ServiceTokenData represents a single service in the token page
type ServiceTokenData struct {
	Name          string
	DisplayName   string
	Instructions  string
	HelpURL       string
	TokenFormat   string
	HasToken      bool
	RequiresToken bool
	AuthType      string // "oauth", "bearer", or "none"
}
