package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/TylerBrock/colorjson"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strings"
	"syscall"
	"time"
)

type PartialJWT struct {
	ExpireAt int64 `json:"exp"`
}

func check(e error) {
	if e != nil {
		fmt.Println(e)
		os.Exit(1)
	}
}

// Explain a kubi token
// if the token is provide as argument, then it explain the provided token
// else it use the token in the default kube configuration
func explainCmd() {
	var token string
	if len(flag.Args()) > 1 {
		token = flag.Arg(1)
		if len(strings.Split(token, ".")) != 3 {
			fmt.Printf("The token: \033[1;36m%s\033[0m is not a valid jwt token.\n", token)
			os.Exit(1)
		}
	} else {
		fmt.Println("Using the kube config file for token explain")
		kubeconfigpath, err := findKubeConfig()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		kubeConfig, err := clientcmd.LoadFromFile(kubeconfigpath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		token = kubeConfig.AuthInfos[kubeConfig.Contexts[kubeConfig.CurrentContext].AuthInfo].Token
	}

	barry, err := jwt.DecodeSegment(strings.Split(token, ".")[1])

	// Deserialize ExpireAt Field only
	var v PartialJWT
	_ = json.Unmarshal(barry, &v)

	tokenTime := time.Unix(v.ExpireAt, 0)
	fmt.Printf("\n\u001B[1;36mStatus:\u001B[0m\n\n")
	fmt.Printf("  Expiration time: %v\n", tokenTime)
	fmt.Printf("  Valid: %v\n", time.Now().Before(tokenTime))

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	f := colorjson.NewFormatter()
	f.Indent = 2

	// Formatting json
	var obj map[string]interface{}
	json.Unmarshal(barry, &obj)

	s, _ := f.Marshal(obj)
	fmt.Println("\n\u001B[1;36mToken body:\u001B[0m\n")
	fmt.Println(string(s))
	fmt.Println("\n")

}

func tokenCmd(kubiUrl *string, username *string, password *string, insecure *bool, useProxy *bool, scopes *string) {

	// Gathering CA for cluster in insecure mode
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	if *useProxy {
		http.DefaultTransport.(*http.Transport).Proxy = http.ProxyFromEnvironment
	} else {
		http.DefaultTransport.(*http.Transport).Proxy = nil
	}
	caResp, err := http.DefaultClient.Get(*kubiUrl + "/ca")
	check(err)
	body, err := ioutil.ReadAll(caResp.Body)
	check(err)
	ca := body

	base, _ := url.Parse(fmt.Sprintf("%v", *kubiUrl))
	base.Path += "token"
	params := url.Values{
		"scopes": []string{*scopes},
	}
	base.RawQuery = params.Encode()
	wurl := base.String()

	req, err := http.NewRequest(http.MethodGet, wurl, nil)
	req.SetBasicAuth(*username, *password)

	var resp *http.Response

	if *insecure {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		if *useProxy {
			transport.Proxy = http.ProxyFromEnvironment
		}
		insecureClient := http.Client{}
		insecureClient.Transport = transport
		resp, err = insecureClient.Do(req)
	} else {
		secureClient := http.Client{}

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
		if *useProxy {
			transport.Proxy = http.ProxyFromEnvironment
		}
		secureClient.Transport = transport
		resp, err = secureClient.Do(req)
	}
	check(err)

	tokenbody, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		fmt.Printf("Error http %d during authentication\n", resp.StatusCode)
		os.Exit(1)
	}

	check(err)
	fmt.Println(string(tokenbody))

}

func configCmd(kubiUrl *string, username *string, password *string, insecure *bool, useProxy *bool) {

	// Gathering CA for cluster in insecure mode
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	if *useProxy {
		http.DefaultTransport.(*http.Transport).Proxy = http.ProxyFromEnvironment
	} else {
		http.DefaultTransport.(*http.Transport).Proxy = nil
	}
	caResp, err := http.DefaultClient.Get(*kubiUrl + "/ca")
	check(err)
	body, err := ioutil.ReadAll(caResp.Body)
	check(err)
	ca := body

	wurl := fmt.Sprintf("%v/config", *kubiUrl)

	req, err := http.NewRequest(http.MethodGet, wurl, nil)
	req.SetBasicAuth(*username, *password)

	var resp *http.Response

	if *insecure {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		if *useProxy {
			transport.Proxy = http.ProxyFromEnvironment
		}
		insecureClient := http.Client{}
		insecureClient.Transport = transport
		resp, err = insecureClient.Do(req)
	} else {
		secureClient := http.Client{}

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
		if *useProxy {
			transport.Proxy = http.ProxyFromEnvironment
		}
		secureClient.Transport = transport
		resp, err = secureClient.Do(req)
	}
	check(err)

	tokenbody, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		fmt.Printf("Error http %d during authentication\n", resp.StatusCode)
		os.Exit(1)
	}

	check(err)

	user, err := user.Current()
	check(err)
	os.MkdirAll(user.HomeDir+"/.kube", 0600)
	f, err := os.Create(user.HomeDir + "/.kube/config")
	check(err)
	f.Write(tokenbody)
	f.Chmod(0600)
	f.Close()
	fmt.Printf("Great ! Your config has been saved in %s\n", f.Name())

}

func main() {

	tokenFalg := flag.NewFlagSet("token", flag.ExitOnError)
	tokenConfig := flag.NewFlagSet("config", flag.ExitOnError)

	flag.Parse()

	switch os.Args[1] {
	case "explain":
		explainCmd()
	case "token":
		kubiUrl := tokenFalg.String("kubi-url", "", "Url to kubi server (ex: https://<kubi-ip>:<kubi-port>")
		insecure := tokenFalg.Bool("insecure", false, "Skip TLS verification")
		username := tokenFalg.String("username", "", "Ldap username ( not dn )")
		password := tokenFalg.String("password", "", "The password, use it at your own risks !")
		scopes := tokenFalg.String("scopes", "", "The token scope ( default user ). For promote, use 'promote'.")
		useProxy := tokenFalg.Bool("use-proxy", false, "Use default proxy or not")
		tokenFalg.Parse(os.Args[2:])

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

		if len(*password) == 0 {
			fmt.Print("Enter your Ldap password: ")
			bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			check(err)
			*password = string(bytePassword)
		}
		tokenCmd(kubiUrl, username, password, insecure, useProxy, scopes)

	case "config":
		kubiUrl := tokenConfig.String("kubi-url", "", "Url to kubi server (ex: https://<kubi-ip>:<kubi-port>")
		insecure := tokenConfig.Bool("insecure", false, "Skip TLS verification")
		username := tokenConfig.String("username", "", "Ldap username ( not dn )")
		password := tokenConfig.String("password", "", "The password, use it at your own risks !")
		useProxy := tokenConfig.Bool("use-proxy", false, "Use default proxy or not")
		tokenConfig.Parse(os.Args[2:])

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

		if len(*password) == 0 {
			fmt.Print("Enter your Ldap password: ")
			bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			check(err)
			*password = string(bytePassword)
		}
		configCmd(kubiUrl, username, password, insecure, useProxy)

	default:
		kubiUrl := flag.String("kubi-url", "", "Url to kubi server (ex: https://<kubi-ip>:<kubi-port>")
		generateConfig := flag.Bool("generate-config", false, "Generate a config in ~/.kube/config")
		insecure := flag.Bool("insecure", false, "Skip TLS verification")
		username := flag.String("username", "", "Ldap username ( not dn )")
		password := flag.String("password", "", "The password, use it at your own risks !")
		useProxy := flag.Bool("use-proxy", false, "Use default proxy or not")
		flag.Parse()
		if *generateConfig {
			fmt.Printf("\033[1;31m%s\033[0m\n", "Deprecated: Please use 'kubi config' instead of 'kubi --generate-config'")
		}
		configCmd(kubiUrl, username, password, insecure, useProxy)
		os.Exit(1)

	}

}

// findKubeConfig finds path from env: KUBECONFIG or ~/.kube/config
func findKubeConfig() (string, error) {
	env := os.Getenv("KUBECONFIG")
	if env != "" {
		return env, nil
	}
	path, err := homedir.Expand("~/.kube/config")
	if err != nil {
		return "", err
	}
	return path, nil
}
