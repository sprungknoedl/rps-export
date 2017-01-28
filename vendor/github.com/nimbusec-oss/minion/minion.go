package minion

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/sessions"
)

func init() {
	gob.Register(Principal{})
}

// PrincipalKey is the key used for the principal in the user session.
const PrincipalKey = "__principal__"

// ErrorFormat defines as which content type an error should be serialized
type ErrorFormat string

const (
	// ErrorAsHTML formats an error using the HTML template `error.html`.
	ErrorAsHTML ErrorFormat = "html"
	// ErrorAsJSON formats the error as JSON object.
	ErrorAsJSON ErrorFormat = "json"
)

// Minion implements basic building blocks that most http servers require
type Minion struct {
	Debug       bool
	LoginURL    string
	ErrorFormat ErrorFormat

	sessions    sessions.Store
	sessionName string
	templates   *template.Template
}

// NewMinion creates a new minion instance.
func NewMinion(sessionName string, sessionKey []byte) Minion {
	return Minion{
		Debug:       os.Getenv("DEBUG") == "true",
		LoginURL:    "/login",
		ErrorFormat: ErrorAsHTML,

		sessions:    sessions.NewCookieStore(sessionKey),
		sessionName: sessionName,
	}
}

// Get retrieves a value from the active session. If the value does not
// exist in the session, a provided default is returned
func (m Minion) Get(w http.ResponseWriter, r *http.Request, name string, def interface{}) interface{} {
	session, err := m.sessions.Get(r, m.sessionName)
	if err != nil {
		return def
	}
	value, ok := session.Values[name]
	if !ok {
		return def
	}
	return value
}

// Set stores a value in the active session.
func (m Minion) Set(w http.ResponseWriter, r *http.Request, name string, value interface{}) {
	session, err := m.sessions.Get(r, m.sessionName)
	if err != nil {
		return
	}

	session.Values[name] = value
	session.Save(r, w)
}

// Delete removes a value from the active session.
func (m Minion) Delete(w http.ResponseWriter, r *http.Request, name string) error {
	session, err := m.sessions.Get(r, m.sessionName)
	if err != nil {
		return err
	}

	delete(session.Values, name)
	return session.Save(r, w)
}

// Secured requires that the user has at least one of the provided roles before
// the request is forwarded to the secured handler.
func (m Minion) Secured(fn http.HandlerFunc, roles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal := m.Get(w, r, PrincipalKey, Principal{}).(Principal)
		if !principal.Authenticated {
			session, err := m.sessions.Get(r, m.sessionName)
			if err != nil {
				m.Error(w, r, http.StatusBadRequest, err)
				return
			}

			session.Values["redirect"] = r.URL.String()
			err = session.Save(r, w)
			if err != nil {
				m.Error(w, r, http.StatusInternalServerError, err)
				return
			}

			http.Redirect(w, r, m.LoginURL, http.StatusSeeOther)
			return
		}

		if !principal.HasAnyRole(roles...) {
			m.HTML(w, r, http.StatusForbidden, "403.html", V{})
			return
		}

		fn(w, r)
	}
}

// Error outputs an error using the default error format (HTML with template
// "error.html" or JSON).
func (m Minion) Error(w http.ResponseWriter, r *http.Request, code int, err error) {
	log.Printf("error: %v", err)
	switch m.ErrorFormat {
	case ErrorAsHTML:
		m.HTML(w, r, code, "error.html", V{
			"code":  code,
			"error": err.Error(),
		})

	case ErrorAsJSON:
		m.JSON(w, r, code, V{
			"code":  code,
			"error": err.Error(),
		})
	}
}

// JSON outputs the data encoded as JSON.
func (m Minion) JSON(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.Header().Add("content-type", "application/json; charset=utf-8")
	w.WriteHeader(code)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to encode json: %v", err)
		log.Printf("failed to encode json: %v", err)
	}
}

// HTML outputs a rendered HTML template to the client. This function also includes
// some default variables into the template scope.
func (m *Minion) HTML(w http.ResponseWriter, r *http.Request, code int, name string, data V) {
	// reload templates in debug mode
	if m.templates == nil || m.Debug {
		fm := template.FuncMap{
			"div": func(dividend, divisor int) float64 {
				return float64(dividend) / float64(divisor)
			},
			"json": func(v interface{}) template.JS {
				b, _ := json.MarshalIndent(v, "", "  ")
				return template.JS(b)
			},
			"dict": func(values ...interface{}) (map[string]interface{}, error) {
				if len(values)%2 != 0 {
					return nil, errors.New("invalid dict call")
				}
				dict := make(map[string]interface{}, len(values)/2)
				for i := 0; i < len(values); i += 2 {
					key, ok := values[i].(string)
					if !ok {
						return nil, errors.New("dict keys must be strings")
					}
					dict[key] = values[i+1]
				}
				return dict, nil
			},
		}

		var err error
		m.templates, err = template.New("").Funcs(fm).ParseGlob("templates/*")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "failed to parse templates: %v", err)
			log.Printf("failed to parse templates: %v", err)
			return
		}
	}

	session, err := m.sessions.Get(r, m.sessionName)
	if err == nil {
		data["flashes"] = session.Flashes()
		session.Save(r, w)
	}

	principal := m.Get(w, r, PrincipalKey, Principal{}).(Principal)
	data["principal"] = principal

	w.Header().Add("content-type", "text/html; charset=utf-8")
	err = m.templates.ExecuteTemplate(w, name, data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to execute template %q: %v", name, err)
		log.Printf("failed to execute template %q: %v", name, err)
		return
	}
}

// Principal is an entity that is authenticated and verified.
type Principal struct {
	Authenticated bool
	ID            string
	Login         string
	Roles         string
}

// HasAnyRole checks whether the principal has any of the given roles. Use '*'
// as a wildcard role to match any.
func (u Principal) HasAnyRole(roles ...string) bool {
	if !u.Authenticated {
		return false
	}

	dedup := make(map[string]struct{})
	for _, role := range strings.Split(u.Roles, " ") {
		dedup[role] = struct{}{}
	}

	for _, role := range roles {
		if _, ok := dedup[role]; ok || role == "*" {
			return true
		}
	}

	return false
}

// BindingResult holds validation errors of the binding process from a HTML
// form to a Go struct.
type BindingResult map[string]string

// Valid returns whether the binding was successfull or not.
func (br BindingResult) Valid() bool {
	return len(br) == 0
}

// Fail marks the binding as failed and stores an error for the given field
// that caused the form binding to fail.
func (br BindingResult) Fail(field, err string) {
	br[field] = err
}

// Include copies all errors and state of a binding result
func (br BindingResult) Include(other BindingResult) {
	for field, err := range other {
		br.Fail(field, err)
	}
}

// V is a helper type to quickly build variable maps for templates.
type V map[string]interface{}

// MarshalJSON implements the json.Marshaler interface.
func (v V) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}(v))
}
