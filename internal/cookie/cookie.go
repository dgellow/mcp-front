package cookie

import (
	"net/http"
	"time"

	"github.com/dgellow/mcp-front/internal"
)

// Common cookie names used in mcp-front
const (
	SessionCookie = "mcp_session"
	CSRFCookie    = "csrf_token"
)

// SetSession sets a session cookie with appropriate security settings
func SetSession(w http.ResponseWriter, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   !internal.IsDevelopmentMode(), // Only require HTTPS in production
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAge.Seconds()),
	})
}

// SetCSRF sets a CSRF token cookie
func SetCSRF(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: false, // CSRF tokens need to be readable by JavaScript
		Secure:   !internal.IsDevelopmentMode(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int((24 * time.Hour).Seconds()), // 24 hours
	})
}

// Clear removes a cookie by setting MaxAge to -1
func Clear(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

// ClearSession removes the session cookie
func ClearSession(w http.ResponseWriter) {
	Clear(w, SessionCookie)
}

// ClearCSRF removes the CSRF cookie
func ClearCSRF(w http.ResponseWriter) {
	Clear(w, CSRFCookie)
}

// Get retrieves a cookie value from the request
func Get(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// GetSession retrieves the session cookie value
func GetSession(r *http.Request) (string, error) {
	return Get(r, SessionCookie)
}

// GetCSRF retrieves the CSRF cookie value
func GetCSRF(r *http.Request) (string, error) {
	return Get(r, CSRFCookie)
}
