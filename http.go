package main

import (
	"crypto/rand"
	"errors"
	"regexp"
	"strconv"

	"golang.org/x/crypto/bcrypt"
	//"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"time"

	"github.com/boltdb/bolt"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/sessions"
	"github.com/pointlander/go-guerrilla/protocol"
)

type MailServer struct {
	state *sessions.CookieStore
}

var routeInboxSingular = regexp.MustCompile(`^/inbox/(\d*)$`)

func (m *MailServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request := path.Clean(r.URL.Path)
	fmt.Println(request)

	authenticate := func() error {
		_, password, ok := r.BasicAuth()
		if !ok {
			return errors.New("authentication failed")
		}
		return emails_db.View(func(tx *bolt.Tx) error {
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
	}

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

		err := authenticate()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			break
		}

		w.Header().Set("Content-Type", "binary")
		w.Write(privateKey.Bytes())
		privateKey = nil
	case request == "/inbox":
		err := authenticate()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			break
		}

		offset := 0
		query := r.URL.Query()
		if page, ok := query["page"]; ok && len(page) > 0 {
			a, err := strconv.Atoi(page[0])
			if err == nil {
				offset = a * 10
			}
		}

		response := &protocol.InboxResponse{}
		err = emails_db.View(func(tx *bolt.Tx) error {
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
			break
		}

		data, err := proto.Marshal(response)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			break
		}

		w.Header().Set("Content-Type", "binary")
		w.Write(data)
	case routeInboxSingular.MatchString(request):
		err := authenticate()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			break
		}

		matches := routeInboxSingular.FindStringSubmatch(request)
		id, err := strconv.Atoi(matches[1])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			break
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
			break
		}
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
