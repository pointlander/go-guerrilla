package main

import (
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/user"
	"reflect"
	"time"

	"github.com/boltdb/bolt"
	"github.com/golang/protobuf/proto"
	"github.com/pointlander/go-guerrilla/protocol"
)

type Context struct {
	client *http.Client
	db     *bolt.DB
}

func (c *Context) Get(url string, message proto.Message, password string) bool {
	var data []byte
	var fresh bool

	c.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("cache"))
		value := bucket.Get([]byte(url))
		if value != nil {
			data = make([]byte, len(value))
			copy(data, value)
		}
		return nil
	})

	var timestamp string
	if data != nil {
		err := proto.Unmarshal(data, message)
		if err != nil {
			log.Fatal(err)
		}

		value := reflect.ValueOf(message).Elem()
		if value = value.FieldByName("Timestamp"); value.IsValid() {
			if value = value.Elem(); value.IsValid() {
				timestamp = time.Unix(value.Int(), 0).Format(time.RFC1123)
			}
		}
	}

	if data == nil || timestamp != "" {
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Fatal(err)
		}
		if timestamp != "" {
			request.Header.Add("If-Modified-Since", timestamp)
		}
		if password != "" {
			request.SetBasicAuth("user", password)
		}
		response, err := c.client.Do(request)
		if err != nil {
			log.Fatal(err)
		}
		if response.StatusCode == http.StatusOK {
			fresh = true
			data, err = ioutil.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				log.Fatal(err)
			}
			err = c.db.Update(func(tx *bolt.Tx) error {
				bucket := tx.Bucket([]byte("cache"))
				err := bucket.Put([]byte(url), data)
				return err
			})
			if err != nil {
				log.Fatal(err)
			}
			err = proto.Unmarshal(data, message)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	return fresh
}

func SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	host, _, _ := net.SplitHostPort(addr)
	if err = c.Hello(host); err != nil {
		return err
	}
	fmt.Println("hello")
	if ok, _ := c.Extension("STARTTLS"); ok {
		tlc := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		}
		if err = c.StartTLS(tlc); err != nil {
			return err
		}
	}
	fmt.Println("tls")
	/*if a != nil && c.ext != nil {
		if _, ok := c.ext["AUTH"]; ok {
			if err = c.Auth(a); err != nil {
				return err
			}
		}
	}*/
	if err = c.Mail(from); err != nil {
		return err
	}
	fmt.Println("mail")
	for _, addr := range to {
		if err = c.Rcpt(addr); err != nil {
			return err
		}
	}
	fmt.Println("rcpt")
	w, err := c.Data()
	if err != nil {
		return err
	}
	fmt.Println("data")
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	fmt.Println("write")
	err = w.Close()
	if err != nil {
		return err
	}
	fmt.Println("close")
	err = c.Quit()
	fmt.Println("quit")
	return err
}

var db *bolt.DB

func send_test_message() {
	smtp_host := "localhost:2525"
	err := SendMail(smtp_host, nil, "andrew@localhost", []string{"andrew@localhost"}, []byte("Subject: test message\nhello world\n.\n"))
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("message sent")
	}
}

var (
	test  = flag.Bool("test", false, "send a test message")
	host  = flag.String("host", "localhost", "the host to connect to")
	index = flag.Int64("index", -1, "view emails")
	view  = flag.Int64("view", -1, "view email")
)

func main() {
	flag.Parse()

	if *test {
		send_test_message()
		return
	}

	http_host := fmt.Sprintf("https://%v:3443", *host)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter password:")
	password, _ := reader.ReadString('\n')

	usr, _ := user.Current()
	if _, err := os.Stat(usr.HomeDir + "/.rebel"); os.IsNotExist(err) {
		os.Mkdir(usr.HomeDir+"/.rebel", os.FileMode(0700))
	}

	db, err := bolt.Open(usr.HomeDir+"/.rebel/base.db", 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("cache"))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}

	ctx := Context{
		client: client,
		db:     db,
	}

	var key rsa.PrivateKey
	var public_key protocol.PublicKey
	var private_key protocol.PrivateKey

	ctx.Get(http_host+"/public_key", &public_key, "")
	key.N = big.NewInt(0)
	key.N.SetBytes(public_key.N)
	key.E = int(*public_key.E)

	ctx.Get(http_host+"/private_key", &private_key, password)
	key.D = big.NewInt(0)
	key.Primes = make([]*big.Int, len(private_key.Primes))
	key.D.SetBytes(private_key.D)
	for i := range private_key.Primes {
		prime := big.NewInt(0)
		prime.SetBytes(private_key.Primes[i])
		key.Primes[i] = prime
	}

	if *index >= 0 {
		var emails protocol.InboxResponse
		request, err := http.NewRequest("GET", fmt.Sprintf("%v/inbox?page=%v", http_host, *index), nil)
		request.SetBasicAuth("user", password)
		response, err := client.Do(request)
		if err != nil {
			log.Fatal(err)
		}
		if response.StatusCode == http.StatusOK {
			data, err := ioutil.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				log.Fatal(err)
			}
			err = proto.Unmarshal(data, &emails)
			if err != nil {
				log.Fatal(err)
			}

			for _, email := range emails.Emails {
				key, err := rsa.DecryptPKCS1v15(rand.Reader, &key, email.Key)
				if err != nil {
					log.Fatal(err)
				}
				cipher, err := aes.NewCipher(key)
				if err != nil {
					log.Fatal(err)
				}
				cipher.Decrypt(email.Data, email.Data)
				decrypted := protocol.Email{}
				err = proto.Unmarshal(email.Data, &decrypted)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("%v: %v\n", *decrypted.Id, *decrypted.Subject)
			}
		}
	}

	if *view >= 0 {
		var email protocol.Encrypted
		request, err := http.NewRequest("GET", fmt.Sprintf("%v/inbox/%v", http_host, *view), nil)
		request.SetBasicAuth("user", password)
		response, err := client.Do(request)
		if err != nil {
			log.Fatal(err)
		}
		if response.StatusCode == http.StatusOK {
			data, err := ioutil.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				log.Fatal(err)
			}
			err = proto.Unmarshal(data, &email)
			if err != nil {
				log.Fatal(err)
			}

			key, err := rsa.DecryptPKCS1v15(rand.Reader, &key, email.Key)
			if err != nil {
				log.Fatal(err)
			}
			cipher, err := aes.NewCipher(key)
			if err != nil {
				log.Fatal(err)
			}
			cipher.Decrypt(email.Data, email.Data)
			decrypted := protocol.Email{}
			err = proto.Unmarshal(email.Data, &decrypted)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf(*decrypted.Mail)
		}
	}
}
