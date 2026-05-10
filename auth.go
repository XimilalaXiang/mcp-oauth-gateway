package main

import (
	"crypto/subtle"
	"html/template"
	"net/http"
)

const loginPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP Gateway - Authorize</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border-radius:16px;padding:2.5rem;width:100%;max-width:420px;box-shadow:0 25px 50px rgba(0,0,0,.3)}
h1{font-size:1.5rem;font-weight:600;margin-bottom:.5rem;color:#f8fafc}
.subtitle{color:#94a3b8;font-size:.875rem;margin-bottom:2rem}
.client-info{background:#0f172a;border-radius:8px;padding:1rem;margin-bottom:1.5rem;font-size:.85rem;color:#94a3b8}
.client-info strong{color:#e2e8f0}
label{display:block;font-size:.875rem;font-weight:500;margin-bottom:.5rem;color:#cbd5e1}
input[type=password]{width:100%;padding:.75rem 1rem;border:1px solid #334155;border-radius:8px;background:#0f172a;color:#f8fafc;font-size:1rem;outline:none;transition:border .2s}
input[type=password]:focus{border-color:#3b82f6}
.btn{width:100%;padding:.75rem;border:none;border-radius:8px;background:#3b82f6;color:#fff;font-size:1rem;font-weight:600;cursor:pointer;margin-top:1.25rem;transition:background .2s}
.btn:hover{background:#2563eb}
.error{background:#7f1d1d;color:#fca5a5;padding:.75rem;border-radius:8px;margin-bottom:1rem;font-size:.875rem}
.scopes{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.5rem}
.scope{background:#1e3a5f;color:#93c5fd;padding:.25rem .625rem;border-radius:4px;font-size:.75rem;font-weight:500}
</style>
</head>
<body>
<div class="card">
<h1>Authorize MCP Access</h1>
<p class="subtitle">An application wants to access your MCP servers</p>
{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
<div class="client-info">
<div><strong>Client:</strong> {{.ClientID}}</div>
<div style="margin-top:.5rem"><strong>Scopes:</strong>
<div class="scopes">{{range .Scopes}}<span class="scope">{{.}}</span>{{end}}</div>
</div>
</div>
<form method="POST" action="/authorize">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
<input type="hidden" name="response_type" value="{{.ResponseType}}">
<input type="hidden" name="scope" value="{{.ScopeRaw}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
<input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
<label for="password">Password</label>
<input type="password" id="password" name="password" placeholder="Enter your password" autofocus required>
<button type="submit" class="btn">Authorize</button>
</form>
</div>
</body>
</html>`

var loginTmpl = template.Must(template.New("login").Parse(loginPageHTML))

type loginData struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	ScopeRaw            string
	Scopes              []string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Error               string
}

func checkPassword(cfg *Config, input string) bool {
	return subtle.ConstantTimeCompare([]byte(cfg.Auth.Password), []byte(input)) == 1
}
