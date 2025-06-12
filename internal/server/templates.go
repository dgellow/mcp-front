package server

import (
	"html/template"
)

var tokenPageTemplate = template.Must(template.New("tokens").Parse(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Service Tokens</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background-color: #fff;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .user-info {
            color: #666;
            font-size: 14px;
        }
        
        .service {
            background-color: #fff;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .service-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .service h2 {
            font-size: 20px;
            margin: 0;
        }
        
        .status {
            font-size: 14px;
            padding: 4px 12px;
            border-radius: 12px;
            font-weight: 500;
        }
        
        .status.configured {
            background-color: #d4f4dd;
            color: #2e7d32;
        }
        
        .status.not-configured {
            background-color: #ffebee;
            color: #c62828;
        }
        
        .instructions {
            margin-bottom: 15px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .instructions a {
            color: #1976d2;
            text-decoration: none;
        }
        
        .instructions a:hover {
            text-decoration: underline;
        }
        
        form {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }
        
        input[type="password"] {
            flex: 1;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        
        input[type="password"]:focus {
            outline: none;
            border-color: #1976d2;
        }
        
        button {
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        
        button.primary {
            background-color: #1976d2;
            color: white;
        }
        
        button.primary:hover {
            background-color: #1565c0;
        }
        
        button.danger {
            background-color: #dc3545;
            color: white;
        }
        
        button.danger:hover {
            background-color: #c82333;
        }
        
        .message {
            padding: 12px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        
        .message.success {
            background-color: #d4f4dd;
            color: #2e7d32;
            border: 1px solid #4caf50;
        }
        
        .message.error {
            background-color: #ffebee;
            color: #c62828;
            border: 1px solid #f44336;
        }
        
        .delete-form {
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>MCP Service Tokens</h1>
            <div class="user-info">Logged in as: {{.UserEmail}}</div>
        </header>
        
        {{if .Message}}
        <div class="message {{.MessageType}}">{{.Message}}</div>
        {{end}}
        
        {{range .Services}}
        <div class="service">
            <div class="service-header">
                <h2>{{.DisplayName}}</h2>
                {{if .HasToken}}
                <span class="status configured">✓ Configured</span>
                {{else}}
                <span class="status not-configured">Not configured</span>
                {{end}}
            </div>
            
            <div class="instructions">
                <p>{{.Instructions}}</p>
                {{if .HelpURL}}
                <p><a href="{{.HelpURL}}" target="_blank">Learn more →</a></p>
                {{end}}
            </div>
            
            <form method="POST" action="/my/tokens/{{.Name}}">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <input type="password" 
                       name="token" 
                       placeholder="{{if .HasToken}}Enter new token to update{{else}}Enter your {{.DisplayName}} token{{end}}"
                       {{if .TokenFormat}}pattern="{{.TokenFormat}}"{{end}}
                       required>
                <button type="submit" class="primary">
                    {{if .HasToken}}Update Token{{else}}Save Token{{end}}
                </button>
            </form>
            
            {{if .HasToken}}
            <form method="POST" action="/my/tokens/{{.Name}}/delete" class="delete-form">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <button type="submit" class="danger">Remove Token</button>
            </form>
            {{end}}
        </div>
        {{end}}
    </div>
</body>
</html>
`))

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
	Name         string
	DisplayName  string
	Instructions string
	HelpURL      string
	TokenFormat  string
	HasToken     bool
}