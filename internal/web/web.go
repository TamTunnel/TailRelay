// Package web serves Tailrelay's management UI: dashboard, clients, settings,
// Tailscale bridge controls. Server-rendered HTML, stdlib net/http.
package web

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/TamTunnel/Tailrelay/internal/config"
	"github.com/TamTunnel/Tailrelay/internal/state"
	"github.com/TamTunnel/Tailrelay/internal/ts"
	"github.com/TamTunnel/Tailrelay/internal/wg"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/style.css static/app.js
var staticFS embed.FS

// Deps wires the web server to the rest of the app.
type Deps struct {
	Store   *state.Store
	WG      *wg.NetOps
	TS      ts.Runner
	Conf    *config.Config
	Version string
}

type session struct {
	csrf    string
	expires time.Time
}

// loginAttempt tracks failed logins from one IP for throttling.
type loginAttempt struct {
	count      int
	lockedTill time.Time
}

// Server is the Tailrelay web UI.
type Server struct {
	d        Deps
	tmpl     *template.Template
	mu       sync.Mutex
	sessions map[string]session
	loginMu  sync.Mutex
	logins   map[string]*loginAttempt
}

// loginBlocked reports whether ip is currently locked out of /login.
// After 5 failures the IP is locked with exponential backoff (1m, 2m, 4m…
// capped at 30m). A successful login resets the counter.
func (s *Server) loginBlocked(ip string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	a, ok := s.logins[ip]
	if !ok {
		return false
	}
	return time.Now().Before(a.lockedTill)
}

func (s *Server) loginFailed(ip string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	a, ok := s.logins[ip]
	if !ok {
		a = &loginAttempt{}
		s.logins[ip] = a
	}
	a.count++
	if a.count >= 5 {
		backoff := time.Minute << (a.count - 5) // 1m, 2m, 4m, …
		if backoff > 30*time.Minute {
			backoff = 30 * time.Minute
		}
		a.lockedTill = time.Now().Add(backoff)
	}
}

func (s *Server) loginSucceeded(ip string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	delete(s.logins, ip)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

const sessionCookie = "tr_session"
const anonCSRFCookie = "tr_csrf"

// NewServer builds the Server and its fully-wrapped http.Handler.
func NewServer(d Deps) (*Server, http.Handler, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, nil, err
	}
	s := &Server{d: d, tmpl: tmpl, sessions: map[string]session{}, logins: map[string]*loginAttempt{}}
	go s.sweepSessions(15 * time.Minute)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/style.css", s.serveCSS)
	mux.HandleFunc("GET /static/app.js", s.serveJS)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST /login", s.handleLoginPost)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /", s.handleDashboard)
	mux.HandleFunc("GET /clients", s.handleClients)
	mux.HandleFunc("POST /clients/add", s.handleClientAdd)
	mux.HandleFunc("POST /clients/delete", s.handleClientDelete)
	mux.HandleFunc("POST /clients/rename", s.handleClientRename)
	mux.HandleFunc("GET /conf/{name}", s.handleConf)
	mux.HandleFunc("GET /qr/{name}", s.handleQR)
	mux.HandleFunc("GET /settings", s.handleSettings)
	mux.HandleFunc("POST /settings", s.handleSettingsPost)
	mux.HandleFunc("POST /ts/exit-node", s.handleExitNode)
	mux.HandleFunc("POST /ts/routes", s.handleRoutes)
	mux.HandleFunc("POST /ts/up", s.handleTailscaleUp)
	mux.HandleFunc("POST /wg/apply", s.handleWGApply)

	var h http.Handler = mux
	h = s.authMiddleware(h)
	h = s.csrfMiddleware(h)
	h = securityHeaders(h)
	h = logRequests(h)
	return s, h, nil
}

// --- middleware ---

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// No inline scripts/styles anywhere (confirm dialogs live in
		// /static/app.js); QR images are same-origin, hence img-src 'self'.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authRequired() bool { return len(s.d.Conf.PasswordHash) > 0 }

// tls reports whether the UI is served over HTTPS, in which case cookies
// must carry the Secure attribute (browsers won't send Secure cookies over
// plain HTTP, so this must track the actual listener).
func (s *Server) tls() bool { return s.d.Conf.TLSEnabled() }

// sessionCSRF returns the CSRF token for a logged-in session.
func (s *Server) sessionCSRF(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok || time.Now().After(sess.expires) {
		delete(s.sessions, c.Value)
		return "", false
	}
	return sess.csrf, true
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authRequired() {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/login" || r.URL.Path == "/static/style.css" {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := s.sessionCSRF(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfToken returns the token to embed in forms, setting the anonymous
// cookie in password-less mode.
func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if s.authRequired() {
		tok, _ := s.sessionCSRF(r)
		return tok
	}
	if c, err := r.Cookie(anonCSRFCookie); err == nil && len(c.Value) == 64 {
		return c.Value
	}
	tok, err := randomToken()
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{Name: anonCSRFCookie, Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.tls()})
	return tok
}

func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return
		}
		var want string
		if s.authRequired() {
			var ok bool
			want, ok = s.sessionCSRF(r)
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		} else if c, err := r.Cookie(anonCSRFCookie); err == nil {
			want = c.Value
		}
		got := r.FormValue("csrf")
		if want == "" || got == "" || !constantTimeEqual(got, want) {
			http.Error(w, "bad csrf token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// --- shared page data ---

type pageData struct {
	Title   string
	Version string
	CSRF    string
	Authed  bool // password auth enabled
	Msg     string
	Err     string
}

func (s *Server) baseData(w http.ResponseWriter, r *http.Request, title string) pageData {
	return pageData{
		Title: title, Version: s.d.Version, CSRF: s.csrfToken(w, r),
		Authed: s.authRequired(),
		Msg:    r.URL.Query().Get("msg"), Err: r.URL.Query().Get("err"),
	}
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

func queryEscape(str string) string {
	var out []byte
	for i := 0; i < len(str); i++ {
		c := str[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-' || c == '_' || c == '.' || c == '~':
			out = append(out, c)
		case c == ' ':
			out = append(out, '+')
		default:
			out = append(out, fmt.Sprintf("%%%02X", c)...)
		}
	}
	return string(out)
}

func redirectMsg(w http.ResponseWriter, r *http.Request, to, msg string) {
	http.Redirect(w, r, to+"?msg="+queryEscape(msg), http.StatusSeeOther)
}

func redirectErr(w http.ResponseWriter, r *http.Request, to string, err error) {
	http.Redirect(w, r, to+"?err="+queryEscape(err.Error()), http.StatusSeeOther)
}

// --- static ---

func (s *Server) serveCSS(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(staticFS, "static/style.css")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Write(data)
}

func (s *Server) serveJS(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(staticFS, "static/app.js")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write(data)
}

// --- login ---

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.authRequired() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", map[string]any{"Err": r.URL.Query().Get("err")})
}

// sweepSessions periodically reaps expired sessions so the in-memory map
// can't grow unboundedly (they're also pruned lazily on access).
func (s *Server) sweepSessions(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for k, v := range s.sessions {
			if now.After(v.expires) {
				delete(s.sessions, k)
			}
		}
		s.mu.Unlock()
		s.loginMu.Lock()
		for k, v := range s.logins {
			if now.After(v.lockedTill) {
				if v.count < 5 {
					delete(s.logins, k) // stale partial counter
				} else {
					v.count = 0 // lock expired: fresh slate, key retained
					v.lockedTill = time.Time{}
				}
			}
		}
		s.loginMu.Unlock()
	}
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.loginBlocked(ip) {
		http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
		return
	}
	if bcrypt.CompareHashAndPassword(s.d.Conf.PasswordHash, []byte(r.FormValue("password"))) != nil {
		s.loginFailed(ip)
		redirectErr(w, r, "/login", fmt.Errorf("wrong password"))
		return
	}
	s.loginSucceeded(ip)
	tok, err := randomToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	csrf, err := randomToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	s.sessions[tok] = session{csrf: csrf, expires: time.Now().Add(12 * time.Hour)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.tls(), MaxAge: 12 * 3600})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	// Secure must match the login cookie or the browser keeps the old one.
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, MaxAge: -1, Path: "/", Secure: s.tls()})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
