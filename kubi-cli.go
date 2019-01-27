package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"strings"
	"syscall"
)
import "fmt"

func check(e error) {
	if e != nil {
		fmt.Println(e)
		os.Exit(1)
	}
}

func main() {

	kubiUrl := flag.String("kubi-url", "", "Url to kubi server (ex: https://<kubi-ip>:<kubi-port>")
	generateConfig := flag.Bool("generate-config", false, "Generate a config in ~/.kube/config")
	username := flag.String("username", "", "Ldap username ( not dn )")
	flag.Parse()

	if len(*username) == 0 {
		fmt.Println("No username found, please add '--username <username>' argument !")
		os.Exit(1)
	}

	if len(*kubiUrl) == 0 {
		fmt.Println("No kubiUrl found, please add '--kubi-url https://<host,fqdn>:<port>' argument !")
		os.Exit(1)
	}
	if !strings.HasPrefix(*kubiUrl, "https://") {
		*kubiUrl = "https://" + *kubiUrl
	}
	err := validation.Validate(&kubiUrl, is.RequestURL)
	check(err)

	fmt.Print("Enter your Ldap password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	check(err)

	// Gathering CA for cluster in insecure mode
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	caResp, err := http.DefaultClient.Get(*kubiUrl + "/ca")
	check(err)
	body, err := ioutil.ReadAll(caResp.Body)
	check(err)
	ca := body

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if ok := rootCAs.AppendCertsFromPEM(ca); !ok {
		log.Println("No certs appended, using system certs only")
	}
	// Trust the augmented cert pool in our client
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	secureClient := http.Client{}
	secureClient.Transport = transport
	req, err := http.NewRequest(http.MethodGet, *kubiUrl+"/config", nil)
	req.SetBasicAuth(*username, string(bytePassword))
	resp, err := secureClient.Do(req)
	check(err)
	tokenbody, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		fmt.Printf("Error http %d during authentication\n", resp.StatusCode)
		fmt.Printf("Details: %v\n", string(tokenbody))
		os.Exit(1)
	}

	check(err)

	if *generateConfig {
		user, err := user.Current()
		check(err)
		f, err := os.Create(user.HomeDir + "/.kube/config")
		check(err)
		f.Write(tokenbody)
		f.Chmod(0600)
		f.Close()
		fmt.Printf("Great ! Your config has been saved in %s\n", f.Name())
	} else {
		fmt.Println("\n\nGreat ! You can use --generate-config to directly save it in ~/.kube/config next time ! \n\n")
		fmt.Println(string(tokenbody))
	}
}
