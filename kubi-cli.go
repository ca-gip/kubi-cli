package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TylerBrock/colorjson"
	"github.com/ca-gip/kubi-cli/internals"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/mitchellh/go-homedir"
	flag "github.com/spf13/pflag"
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

// Explain a kubi token
// if the token is provide as argument, then it explain the provided token
// else it use the token in the default kube configuration
func explainCmd(flagSet *flag.FlagSet) {
	var token string
	if len(flagSet.Args()) == 1 {
		token = flagSet.Arg(0)
		if len(strings.Split(token, ".")) != 3 {
			internal.ExitIfError(errors.New(fmt.Sprintf("The token: %s is not a valid jwt token.\n", token)))
		}
	} else {
		internal.LogLightGray("Using the kube config file for token explain")
		kubeconfigpath, err := findKubeConfig()
		internal.ExitIfError(err)

		kubeConfig, err := clientcmd.LoadFromFile(kubeconfigpath)
		internal.ExitIfError(err)

		if kubeConfig.CurrentContext == internal.EmptyString {
			internal.ExitIfError(errors.New("No current context found in kubeconfig"))
		}
		token = kubeConfig.AuthInfos[kubeConfig.Contexts[kubeConfig.CurrentContext].AuthInfo].Token
		if token == internal.EmptyString {
			internal.ExitIfError(errors.New(fmt.Sprintf("No token found for the context: %s", kubeConfig.CurrentContext)))
		}
		token = kubeConfig.AuthInfos[kubeConfig.Contexts[kubeConfig.CurrentContext].AuthInfo].Token
	}

	tokenTxt, err := jwt.DecodeSegment(strings.Split(token, ".")[1])

	// Deserialize ExpireAt Field only
	var v PartialJWT
	_ = json.Unmarshal(tokenTxt, &v)

	internal.LogWhite("\nRaw Token:\n")
	internal.LogNormal(token)

	tokenTime := time.Unix(v.ExpireAt, 0)
	internal.LogWhite("\nStatus:\n")
	internal.LogNormal("  Expiration time: ", tokenTime.String())
	internal.LogNormal("  Valid: ", time.Now().Before(tokenTime))
	internal.ExitIfError(err)

	f := colorjson.NewFormatter()
	f.Indent = 2

	// Formatting json
	var obj map[string]interface{}
	json.Unmarshal(tokenTxt, &obj)

	s, _ := f.Marshal(obj)
	fmt.Println("\n\u001B[1;36mToken body:\u001B[0m\n")
	fmt.Println(string(s))
	fmt.Println("\n")

}

func tokenCmd(flagSet *flag.FlagSet, kubiUrl *string, username *string, password *string, insecure *bool, useProxy *bool, scopes *string, update bool) {
	if len(*username) == 0 {
		internal.LogRed("No username found, please add '--username <username>' argument !")
		internal.LogWhite("Supported Args:\n")
		flagSet.PrintDefaults()
		os.Exit(1)
	}
	if len(*kubiUrl) == 0 {
		internal.LogRed("No kubiUrl found, please add '--kubi-url https://<host,fqdn>:<port>' argument !")
		internal.LogWhite("Supported Args:\n")
		flagSet.PrintDefaults()
		os.Exit(1)
	}
	// Gathering CA for cluster in insecure mode
	if !strings.HasPrefix(*kubiUrl, "https://") {
		*kubiUrl = "https://" + *kubiUrl
	}
	err := validation.Validate(&kubiUrl, is.RequestURL)
	internal.ExitIfError(err)
	readPasswordIfEmpty(password)

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	if *useProxy {
		http.DefaultTransport.(*http.Transport).Proxy = http.ProxyFromEnvironment
	} else {
		http.DefaultTransport.(*http.Transport).Proxy = nil
	}
	internal.ExitIfError(err)

	caResp, err := http.DefaultClient.Get(*kubiUrl + "/ca")
	internal.ExitIfError(err)
	body, err := ioutil.ReadAll(caResp.Body)
	internal.ExitIfError(err)
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
	internal.ExitIfError(err)

	tokenbody, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		internal.LogRed(fmt.Sprintf("Error http %d during authentication\n", resp.StatusCode))
		os.Exit(1)
	}

	if update {
		internal.LogLightGray("Rotating token in kube config file")
		kubeconfigpath, err := findKubeConfig()
		internal.ExitIfError(err)

		kubeConfig, err := clientcmd.LoadFromFile(kubeconfigpath)
		internal.ExitIfError(err)

		clusterName := strings.TrimPrefix(*kubiUrl, "https://kubi.")
		username := fmt.Sprintf("%s_%s", *username, clusterName)

		kubeConfig.AuthInfos[kubeConfig.Contexts[username].AuthInfo].Token = string(tokenbody)
		clientcmd.WriteToFile(*kubeConfig, kubeconfigpath)
		internal.LogYellow("The token has successfully been rotated !")
		os.Exit(0)
	}

	internal.ExitIfError(err)
	internal.LogLightGray(string(tokenbody))

}

func configCmd(flagSet *flag.FlagSet, kubiUrl *string, username *string, password *string, insecure *bool, useProxy *bool) {
	if len(*username) == 0 {
		internal.LogRed("No username found, please add '--username <username>' argument !")
		internal.LogWhite("Supported Args:\n")
		flagSet.PrintDefaults()
		os.Exit(1)
	}
	if len(*kubiUrl) == 0 {
		internal.LogRed("No kubiUrl found, please add '--kubi-url https://<host,fqdn>:<port>' argument !")
		internal.LogWhite("Supported Args:\n")
		flagSet.PrintDefaults()
		os.Exit(1)
	}
	// Gathering CA for cluster in insecure mode
	if !strings.HasPrefix(*kubiUrl, "https://") {
		*kubiUrl = "https://" + *kubiUrl
	}
	err := validation.Validate(&kubiUrl, is.RequestURL)
	internal.ExitIfError(err)
	readPasswordIfEmpty(password)
	// Gathering CA for cluster in insecure mode
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	if *useProxy {
		http.DefaultTransport.(*http.Transport).Proxy = http.ProxyFromEnvironment
	} else {
		http.DefaultTransport.(*http.Transport).Proxy = nil
	}
	caResp, err := http.DefaultClient.Get(*kubiUrl + "/ca")
	internal.ExitIfError(err)
	body, err := ioutil.ReadAll(caResp.Body)
	internal.ExitIfError(err)
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
	internal.ExitIfError(err)

	tokenbody, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		internal.LogRed(fmt.Sprintf("Error http %d during authentication\n", resp.StatusCode))
		os.Exit(1)
	}

	internal.ExitIfError(err)

	user, err := user.Current()
	internal.ExitIfError(err)

	kubeconfigpath, err := findKubeConfig()
	internal.ExitIfError(err)

	if !internal.FileExists(kubeconfigpath) {
		internal.LogNormal("Kubeconfig doesn't existing, it will be created.")
		os.MkdirAll(user.HomeDir+"/.kube", 0600)
		f, err := os.Create(user.HomeDir + "/.kube/config")
		internal.ExitIfError(err)
		f.Chmod(0600)
		internal.ExitIfError(err)

		newKubeConfig, err := clientcmd.Load(tokenbody)
		internal.ExitIfError(err)
		clientcmd.WriteToFile(*newKubeConfig, kubeconfigpath)

		internal.LogReturn()
		internal.LogYellow("Great ! Your config has been created in ", kubeconfigpath)
		internal.LogReturn()

	} else {
		existingKubeConfig, err := clientcmd.LoadFromFile(kubeconfigpath)
		internal.ExitIfError(err)
		newKubeConfig, err := clientcmd.Load(tokenbody)
		internal.ExitIfError(err)

		// Merging Clusters
		for key, value := range newKubeConfig.Clusters {
			existingKubeConfig.Clusters[key] = value
		}

		// Merging Context
		for key, value := range newKubeConfig.Contexts {
			existingKubeConfig.Contexts[key] = value
		}

		// Merging Users
		for key, value := range newKubeConfig.AuthInfos {
			existingKubeConfig.AuthInfos[key] = value
		}

		clientcmd.WriteToFile(*existingKubeConfig, kubeconfigpath)
		internal.LogReturn()
		internal.LogYellow("Great ! Your config has been updated in ", kubeconfigpath)
		internal.LogReturn()
	}

}

func main() {

	commonFlags := flag.NewFlagSet("commonFlags", flag.ExitOnError)
	tokenFlags := flag.NewFlagSet("token", flag.ExitOnError)
	configFlags := flag.NewFlagSet("config", flag.ExitOnError)
	explainFlags := flag.NewFlagSet("explain", flag.ExitOnError)
	oldFlags := flag.NewFlagSet("old", flag.ExitOnError)
	versionFlags := flag.NewFlagSet("version", flag.ExitOnError)

	kubiUrl := commonFlags.String("kubi-url", internal.EmptyString, "Url to kubi server (ex: https://<kubi-ip>:<kubi-port>")
	insecure := commonFlags.Bool("insecure", false, "Skip TLS verification")
	username := commonFlags.String("username", internal.EmptyString, "Your username for connection")
	password := commonFlags.String("password", internal.EmptyString, "The password, use it at your own risks !")
	useProxy := commonFlags.Bool("use-proxy", false, "Use default proxy or not")

	tokenFlags.AddFlagSet(commonFlags)
	configFlags.AddFlagSet(commonFlags)
	oldFlags.AddFlagSet(commonFlags)

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "explain":
			explainFlags.Parse(os.Args[2:])
			explainCmd(explainFlags)
		case "token":
			scopes := tokenFlags.String("scopes", internal.EmptyString, "The token scope ( default user ). For promote, use 'promote'.")
			update := tokenFlags.Bool("update", false, "Update token directly in config")
			tokenFlags.Parse(os.Args[2:])
			tokenCmd(tokenFlags, kubiUrl, username, password, insecure, useProxy, scopes, *update)

		case "config":
			configFlags.Parse(os.Args[2:])
			configCmd(configFlags, kubiUrl, username, password, insecure, useProxy)

		case "version":
			versionFlags.Parse(os.Args[2:])
			internal.LogLightGray("1.8.3")
			os.Exit(0)
		default:
			generateConfig := oldFlags.Bool("generate-config", false, "Generate a config in ~/.kube/config")
			generateToken := oldFlags.Bool("generate-token", false, "Generate a token only")
			oldFlags.Parse(os.Args[1:])
			if *generateConfig {
				internal.LogReturn()
				internal.LogRed("Deprecated: Please use 'kubi config' instead of 'kubi --generate-config'")
				internal.LogReturn()

			}
			if *generateToken {
				configCmd(oldFlags, kubiUrl, username, password, insecure, useProxy)
			} else if *generateConfig {
				configCmd(oldFlags, kubiUrl, username, password, insecure, useProxy)
			} else {
				internal.LogReturn()
				internal.LogRed("\tThe usage of old command style is deprecated: please use kubi token, kubi config or kubi explain")
				internal.LogRed("\tYou should use --generate-token or --generate-config, for scopes, use only --scopes parameter\n")
				os.Exit(1)
			}
		}
	} else {
		internal.LogLightRed("\nNo argument specified, please the documentation:")
		internal.LogWhite("\n  kubi token: Generate / Update a kubi token\n  args:")
		tokenFlags.PrintDefaults()
		internal.LogWhite("\n  kubi config: Generate / Update a kube config\n  args:")
		configFlags.PrintDefaults()
		internal.LogWhite("\n  kubi explain: Generate / Update a kube config\n")
		internal.LogWhite("\n  kubi version: show version of kubi\n")
	}

}

func readPasswordIfEmpty(password *string) {
	if len(*password) == 0 {
		fmt.Print("Enter your password: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		internal.ExitIfError(err)
		*password = string(bytePassword)
	}
}

// findKubeConfig finds path from env: KUBECONFIG or ~/.kube/config
func findKubeConfig() (string, error) {
	env := os.Getenv("KUBECONFIG")
	if env != internal.EmptyString {
		return env, nil
	}
	path, err := homedir.Expand("~/.kube/config")
	if err != nil {
		return internal.EmptyString, err
	}
	return path, nil
}
