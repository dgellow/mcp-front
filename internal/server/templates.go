package server

import (
	_ "embed"
	"html/template"
)

//go:embed templates/tokens.html
var tokenPageTemplateHTML string

//go:embed templates/admin.html
var adminPageTemplateHTML string

//go:embed templates/services.html
var servicesPageTemplateHTML string

var tokenPageTemplate = template.Must(template.New("tokens").Parse(tokenPageTemplateHTML))
var adminPageTemplate = template.Must(template.New("admin").Parse(adminPageTemplateHTML))
var servicesPageTemplate = template.Must(template.New("services").Parse(servicesPageTemplateHTML))

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
	Name             string
	DisplayName      string
	Instructions     string
	HelpURL          string
	TokenFormat      string
	HasToken         bool
	RequiresToken    bool
	AuthType         string // "oauth", "bearer", or "none"
	SupportsOAuth    bool   // Whether this service supports OAuth authentication
	IsOAuthConnected bool   // Whether the user has connected OAuth for this service
}

// ServicesPageData represents the data for the service selection page
type ServicesPageData struct {
	Services  []ServiceSelectionData
	State     string
	ReturnURL string
}

// ServiceSelectionData represents a single service in the selection page
type ServiceSelectionData struct {
	Name        string
	DisplayName string
	Status      string // "not_connected", "connected", "error"
	ErrorMsg    string
}
