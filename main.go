package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/nimbusec-oss/minion"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// RPSLoginURL is the URL the login form send the login data
	RPSLoginURL = "https://dienstplan.o.roteskreuz.at/login.php"
	// RPSCalendarURL is the URL where the upcoming duties are downloaded as iCal.
	RPSCalendarURL = "https://dienstplan.o.roteskreuz.at/mais/nextJobs.php?ics=true"
)

// App holds the SecretKey used to encrypt and decrypt the login data part of the
// calendar URLs.
type App struct {
	minion.Minion
	SecretKey [32]byte
}

func main() {
	listenAddress := ":" + os.Getenv("PORT")
	key, err := hex.DecodeString(os.Getenv("SECRET_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	app := App{Minion: minion.NewMinion("rkd", key)}
	copy(app.SecretKey[:], key)

	http.HandleFunc("/ical", Logging(app.ProxyICS))
	http.HandleFunc("/", Logging(app.Index))
	http.ListenAndServe(listenAddress, nil)
}

// Logging is a simple logging middleware.
func Logging(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := httpsnoop.CaptureMetrics(fn, w, r)
		log.Printf("⇄ %s %s ⇢ %d in %v",
			r.Method,
			r.URL.String(),
			m.Code,
			m.Duration)
	}
}

// Index serves the login form and the generated URL for the
// calendar.
func (app App) Index(w http.ResponseWriter, r *http.Request) {
	url := ""
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			app.Error(w, r, http.StatusBadRequest, err)
			return
		}

		log.Printf("⇒ validating login for user %s", r.FormValue("loginname"))
		err = LoginToRPS(http.DefaultClient, r.Form)
		if err != nil {
			app.Error(w, r, http.StatusBadRequest, err)
			return
		}

		encrypted, err := EncryptForm(r.Form, &app.SecretKey)
		if err != nil {
			app.Error(w, r, http.StatusInternalServerError, err)
			return
		}

		log.Printf("⇒ created calendar url for user %s", r.FormValue("loginname"))
		url = os.Getenv("BASE_URL") + "/ical?" + string(encrypted)
	}

	app.HTML(w, r, http.StatusOK, "index.html", minion.V{
		"url": url,
	})
}

// ProxyICS proxies the calendar from RPS to the caller. The login to RPS
// happens via the provided encrypted form data as part of the query.
func (app App) ProxyICS(w http.ResponseWriter, r *http.Request) {
	form, err := DecryptForm(r.URL.RawQuery, &app.SecretKey)
	if err != nil {
		app.Error(w, r, http.StatusBadRequest, err)
		return
	}

	log.Printf("⇒ fetching calendar for user %s", form.Get("loginname"))

	jar, err := cookiejar.New(nil)
	if err != nil {
		app.Error(w, r, http.StatusInternalServerError, err)
		return
	}

	client := &http.Client{
		Jar:     jar,
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// login
	err = LoginToRPS(client, form)
	if err != nil {
		app.Error(w, r, http.StatusBadGateway, err)
		return
	}

	// ics download
	resp, err := client.Get(RPSCalendarURL)
	if err != nil {
		app.Error(w, r, http.StatusBadGateway, err)
		return
	}

	w.Header().Add("Content-Type", "text/calendar")
	w.Header().Add("Content-Disposition", "attachment; filename=rps-export.ics")
	io.Copy(w, resp.Body)
	resp.Body.Close()
}

// EncryptForm encrypts the form an returns an string that is safe to
// include in the query part of the URL.
func EncryptForm(values url.Values, key *[32]byte) (string, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}

	body := []byte(values.Encode())
	encrypted := secretbox.Seal(nonce[:], body, &nonce, key)
	msg := base64.RawURLEncoding.EncodeToString(encrypted)
	return msg, nil
}

// DecryptForm decrypts an encrypted form query string.
func DecryptForm(msg string, key *[32]byte) (url.Values, error) {
	encrypted, err := base64.RawURLEncoding.DecodeString(msg)
	if err != nil {
		return url.Values{}, err
	}

	var nonce [24]byte
	copy(nonce[:], encrypted[:24])

	decrypted, ok := secretbox.Open([]byte{}, encrypted[24:], &nonce, key)
	if !ok {
		return url.Values{}, errors.New("decryption error")
	}
	return url.ParseQuery(string(decrypted))
}

// LoginToRPS tries to login to RPS with the provided form data or
// returns an error.
func LoginToRPS(client *http.Client, form url.Values) error {
	resp, err := client.PostForm(RPSLoginURL, form)
	if err != nil {
		return err
	}

	buf := &bytes.Buffer{}
	io.Copy(buf, resp.Body)
	resp.Body.Close()

	if !strings.Contains(buf.String(), "Logout") {
		return errors.New("Ungültige Zugangsdaten")
	}

	return nil
}
