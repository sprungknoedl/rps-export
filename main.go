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

	"github.com/nimbusec-oss/minion"
	"golang.org/x/crypto/nacl/secretbox"
)

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

	app := App{
		Minion: minion.NewMinion("rkd", key),
	}

	copy(app.SecretKey[:], key)

	http.HandleFunc("/ical", app.ProxyICS)
	http.HandleFunc("/", app.Index)
	http.ListenAndServe(listenAddress, nil)
}

func (app App) Index(w http.ResponseWriter, r *http.Request) {
	url := ""
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			app.Error(w, r, http.StatusBadRequest, err)
			return
		}

		err = LoginToRPS(http.DefaultClient, r.Form)
		if err != nil {
			app.Error(w, r, http.StatusBadRequest, err)
			return
		}

		encrypted, err := Encrypt(r.Form, &app.SecretKey)
		if err != nil {
			app.Error(w, r, http.StatusInternalServerError, err)
			return
		}

		url = os.Getenv("BASE_URL") + "/ical?" + string(encrypted)
	}

	app.HTML(w, r, http.StatusOK, "index.html", minion.V{
		"url": url,
	})
}

func (app App) ProxyICS(w http.ResponseWriter, r *http.Request) {
	form, err := Decrypt(r.URL.RawQuery, &app.SecretKey)
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

	client := http.Client{
		Jar:     jar,
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// login
	resp, err := client.PostForm("https://dienstplan.o.roteskreuz.at/login.php", form)
	if err != nil {
		app.Error(w, r, http.StatusBadGateway, err)
		return
	}
	resp.Body.Close()

	// ics download
	resp, err = client.Get("https://dienstplan.o.roteskreuz.at/mais/nextJobs.php?ics=true")
	if err != nil {
		app.Error(w, r, http.StatusBadGateway, err)
		return
	}

	w.Header().Add("Content-Type", "text/calendar")
	w.Header().Add("Content-Disposition", "attachment; filename=rps-export.ics")
	io.Copy(w, resp.Body)
	resp.Body.Close()
}

func Encrypt(values url.Values, key *[32]byte) (string, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}

	body := []byte(values.Encode())
	encrypted := secretbox.Seal(nonce[:], body, &nonce, key)
	msg := base64.RawURLEncoding.EncodeToString(encrypted)
	return msg, nil
}

func Decrypt(msg string, key *[32]byte) (url.Values, error) {
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

func LoginToRPS(client *http.Client, form url.Values) error {
	resp, err := client.PostForm("https://dienstplan.o.roteskreuz.at/login.php", form)
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
