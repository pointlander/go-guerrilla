package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
)

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
			ServerName: host,
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

func main() {
	err := SendMail("localhost:2525", nil, "andrew@localhost", []string{"andrew@localhost"}, []byte("hello world\n.\n"))
	if err != nil {
		fmt.Println(err)
		return
	} else {
		fmt.Println("message sent")
	}
}
