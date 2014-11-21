package main

import (
	"crypto/rand"
	"fmt"
	"github.com/gorilla/sessions"
	"io"
	"log"
	"net/http"
	"path"
	"time"
)

type MailServer struct {
	state *sessions.CookieStore
}

func (m *MailServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request := path.Clean(r.URL.Path)
	fmt.Println(request)

	switch true {
	case request == "/login":
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
	server := http.Server {
		Addr: ":3443",
		Handler: mail_server,
		ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	server.ListenAndServeTLS(gConfig["GSMTP_PUB_KEY"], gConfig["GSMTP_PRV_KEY"])
}
