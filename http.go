package main

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/boltdb/bolt"
	"github.com/golang/protobuf/proto"
	"github.com/julienschmidt/httprouter"
	"github.com/pointlander/go-guerrilla/protocol"
	"golang.org/x/crypto/bcrypt"
)

func routePublicKey(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	err := emails_db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("meta"))
		publicKey := bucket.Get([]byte("email_public_key"))
		if publicKey == nil {
			return errors.New("public key not found")
		}
		w.Header().Set("Content-Type", "binary")
		w.Write(publicKey)

		return nil
	})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func routePrivateKey(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if privateKey == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "binary")
	w.Write(privateKey.Bytes())
	privateKey = nil
}

func routeInbox(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	offset := 0
	query := r.URL.Query()
	if page, ok := query["page"]; ok && len(page) > 0 {
		a, err := strconv.Atoi(page[0])
		if err == nil {
			offset = a * 10
		}
	}

	response := &protocol.InboxResponse{}
	err := emails_db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("inbox"))
		last, cursor := bucket.Sequence(), bucket.Cursor()
		key, value := cursor.Seek(itob(last - uint64(offset)))
		if key == nil {
			return errors.New("invalid key")
		}
		cp, encrypted := make([]byte, len(value)), &protocol.Encrypted{}
		copy(cp, value)
		err := proto.Unmarshal(cp, encrypted)
		if err != nil {
			return err
		}
		response.Emails = append(response.Emails, encrypted)
		for c := 0; c < 9; c++ {
			key, value = cursor.Prev()
			if key == nil {
				break
			}
			cp, encrypted = make([]byte, len(value)), &protocol.Encrypted{}
			copy(cp, value)
			err = proto.Unmarshal(cp, encrypted)
			if err != nil {
				return err
			}
			response.Emails = append(response.Emails, encrypted)
		}

		return nil
	})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	data, err := proto.Marshal(response)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "binary")
	w.Write(data)
}

func routeInboxSingular(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id, err := strconv.Atoi(ps.ByName("id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = emails_db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("inbox"))
		value := bucket.Get(itob(uint64(id)))
		if value == nil {
			return errors.New("invalid key")
		}
		w.Header().Set("Content-Type", "binary")
		w.Write(value)

		return nil
	})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func basicAuth(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		failed := func() {
			w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}

		_, password, ok := r.BasicAuth()
		if !ok {
			failed()
			return
		}

		err := emails_db.View(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte("meta"))
			hashedPassword := bucket.Get([]byte("password"))
			if hashedPassword == nil {
				return errors.New("authentication failed")
			}
			err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
			if err != nil {
				return errors.New("authentication failed")
			}

			return nil
		})
		if err != nil {
			failed()
			return
		}

		h(w, r, ps)
	}
}

func startMailServer() {
	router := httprouter.New()
	router.GET("/public_key", routePublicKey)
	router.GET("/private_key", basicAuth(routePrivateKey))
	router.GET("/inbox", basicAuth(routeInbox))
	router.GET("/inbox/:id", basicAuth(routeInboxSingular))

	server := http.Server{
		Addr:           ":3443",
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	server.ListenAndServeTLS(gConfig["GSMTP_PUB_KEY"], gConfig["GSMTP_PRV_KEY"])
}
