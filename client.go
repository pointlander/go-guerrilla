package main

import (
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/user"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/chzyer/readline"
	"github.com/golang/protobuf/proto"
	"github.com/jaytaylor/html2text"
	"github.com/pointlander/go-guerrilla/protocol"
	goemail "github.com/veqryn/go-email/email"
)

type Context struct {
	client         *http.Client
	host, password string
	key            rsa.PrivateKey
	db             *bolt.DB
}

func (c *Context) Connect() {
	var public protocol.PublicKey
	c.Get(c.host+"/public_key", &public, "")
	c.key.N = big.NewInt(0)
	c.key.N.SetBytes(public.N)
	c.key.E = int(*public.E)

	var private protocol.PrivateKey
	c.Get(c.host+"/private_key", &private, c.password)
	c.key.D = big.NewInt(0)
	c.key.Primes = make([]*big.Int, len(private.Primes))
	c.key.D.SetBytes(private.D)
	for i := range private.Primes {
		prime := big.NewInt(0)
		prime.SetBytes(private.Primes[i])
		c.key.Primes[i] = prime
	}
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

func (c *Context) Index(i int) {
	request, err := http.NewRequest("GET", fmt.Sprintf("%v/inbox?page=%v", c.host, i), nil)
	if err != nil {
		log.Panic(err)
	}
	request.SetBasicAuth("user", c.password)

	response, err := c.client.Do(request)
	if err != nil {
		log.Panic(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return
	}

	size, email, decrypted := make([]byte, 8), protocol.Encrypted{}, protocol.Email{}
	for {
		n, err := io.ReadFull(response.Body, size)
		if n == 0 {
			break
		} else if err != nil {
			log.Panic(err)
		}

		buffer := make([]byte, btoi(size))
		_, err = io.ReadFull(response.Body, buffer)
		if err != nil {
			log.Panic(err)
		}

		err = proto.Unmarshal(buffer, &email)
		if err != nil {
			log.Panic(err)
		}

		key, err := rsa.DecryptPKCS1v15(rand.Reader, &c.key, email.Key)
		if err != nil {
			log.Panic(err)
		}
		cipher, err := aes.NewCipher(key)
		if err != nil {
			log.Panic(err)
		}
		cipher.Decrypt(email.Data, email.Data)

		err = proto.Unmarshal(email.Data, &decrypted)
		if err != nil {
			log.Panic(err)
		}
		fmt.Printf("%v: %v %v %v\n\n", *decrypted.Id, *decrypted.Subject,
			*decrypted.From, *decrypted.To)
	}
}

func (c *Context) View(i int) {
	var email protocol.Encrypted
	request, err := http.NewRequest("GET", fmt.Sprintf("%v/inbox/%v", c.host, i), nil)
	request.SetBasicAuth("user", c.password)
	response, err := c.client.Do(request)
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

		key, err := rsa.DecryptPKCS1v15(rand.Reader, &c.key, email.Key)
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

		process := func(mediaType string, body []byte) {
			fmt.Println(mediaType)
			if mediaType == "text/plain" {
				fmt.Println(string(body))
			} else if mediaType == "text/html" {
				text, err := html2text.FromString(string(body))
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(text)
			}
		}
		message, err := goemail.ParseMessage(strings.NewReader(*decrypted.Mail))
		if err != nil {
			log.Fatal(err)
		}
		if message.HasBody() {
			mediaType, _, _ := message.Header.ContentType()
			process(mediaType, message.Body)
		} else {
			for _, part := range message.MessagesAll() {
				mediaType, _, err := part.Header.ContentType()
				if err != nil {
					log.Fatal(err)
				}
				process(mediaType, part.Body)
			}
		}
	}
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

func TestServer() {
	smtp_host := "localhost:2525"
	err := SendMail(smtp_host, nil, "andrew@localhost", []string{"andrew@localhost"}, []byte("Subject: test message\nhello world\n.\n"))
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("message sent")
	}
}

func EmailClient() {
	usr, _ := user.Current()
	if _, err := os.Stat(usr.HomeDir + "/.go-guerrilla"); os.IsNotExist(err) {
		os.Mkdir(usr.HomeDir+"/.go-guerrilla", os.FileMode(0700))
	}

	db, err := bolt.Open(usr.HomeDir+"/.go-guerrilla/client.db", 0600, nil)
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

	rl, err := readline.New("> ")
	if err != nil {
		log.Fatal(err)
	}
	defer rl.Close()
	reader := bufio.NewReader(os.Stdin)

	for {
		line, err := rl.Readline()
		if err != nil {
			break
		}

		parts := strings.Split(line, " ")
		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "connect":
			if len(parts) != 2 {
				fmt.Println("index <host>")
				break
			}
			ctx.host = fmt.Sprintf("https://%v:3443", parts[1])
			fmt.Print("Enter password:")
			ctx.password, _ = reader.ReadString('\n')
			ctx.Connect()
		case "index":
			if len(parts) != 2 {
				fmt.Println("index <page number>")
				break
			}
			i, err := strconv.Atoi(parts[1])
			if err != nil {
				log.Fatal(err)
			}
			ctx.Index(i)
		case "view":
			if len(parts) != 2 {
				fmt.Println("view <email id>")
				break
			}
			i, err := strconv.Atoi(parts[1])
			if err != nil {
				log.Fatal(err)
			}
			ctx.View(i)
		case "exit":
			return
		}
	}
}
