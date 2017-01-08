package main

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/bcrypt"
	//"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gorilla/sessions"
)

type MailServer struct {
	state *sessions.CookieStore
}

func (m *MailServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request := path.Clean(r.URL.Path)
	fmt.Println(request)

	switch true {
	case request == "/public_key":
		err := emails_db.View(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte("meta"))
			public_key := bucket.Get([]byte("email_public_key"))
			if public_key == nil {
				return errors.New("public key not found")
			}
			w.Header().Set("Content-Type", "binary")
			//buffer := make([]byte, base64.StdEncoding.EncodedLen(len(public_key)))
			//base64.StdEncoding.Encode(buffer, public_key)
			w.Write(public_key)

			return nil
		})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
		}
	case request == "/private_key":
		if privateKey == nil {
			w.WriteHeader(http.StatusBadRequest)
			break
		}
		_, password, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			break
		}
		var hashedPassword []byte
		emails_db.View(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte("meta"))
			hashedPassword = bucket.Get([]byte("password"))
			return nil
		})
		if hashedPassword == nil {
			w.WriteHeader(http.StatusBadRequest)
			break
		}
		err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			break
		}
		w.Header().Set("Content-Type", "binary")
		w.Write(privateKey.Bytes())
		privateKey = nil
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func start_mail_server() {
	akey, ekey := make([]byte, 64), make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, akey); err != nil {
		log.Fatal("failed to generate authentication key")
	}
	if _, err := io.ReadFull(rand.Reader, ekey); err != nil {
		log.Fatal("failed to generate encryption key")
	}

	mail_server := &MailServer{
		state: sessions.NewCookieStore(akey, ekey),
	}
	server := http.Server{
		Addr:           ":3443",
		Handler:        mail_server,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	server.ListenAndServeTLS(gConfig["GSMTP_PUB_KEY"], gConfig["GSMTP_PRV_KEY"])
}
