package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strings"
	"syscall"
	"time"

	"github.com/TylerBrock/colorjson"
	internal "github.com/ca-gip/kubi-cli/internals"
	"github.com/dgrijalva/jwt-go"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/mitchellh/go-homedir"
	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/ssh/terminal"
	"k8s.io/client-go/tools/clientcmd"
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
			internal.ExitIfError(fmt.Errorf("the token: %s is not a valid jwt token.\n", token))
		}
	} else {
		internal.LogLightGray("Using the kube config file for token explain")
		kubeconfigpath, err := findKubeConfig()
		internal.ExitIfError(err)

		kubeConfig, err := clientcmd.LoadFromFile(kubeconfigpath)
		internal.ExitIfError(err)

		if kubeConfig.CurrentContext == internal.EmptyString {
			internal.ExitIfError(errors.New("no current context found in kubeconfig"))
		}
		token = kubeConfig.AuthInfos[kubeConfig.Contexts[kubeConfig.CurrentContext].AuthInfo].Token
		if token == internal.EmptyString {
			internal.ExitIfError(fmt.Errorf("no token found for the context: %s", kubeConfig.CurrentContext))
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
	err = json.Unmarshal(tokenTxt, &obj)
	internal.ExitIfError(err)

	s, _ := f.Marshal(obj)
	internal.LogBlue("\nToken body:\n")
	fmt.Println(string(s))
}

func tokenCmd(flagSet *flag.FlagSet, kubiURL *string, username *string, password *string, insecure *bool, useProxy *bool, scopes *string, update bool) {
	if len(*username) == 0 {
		internal.LogRed("No username found, please add '--username <username>' argument !")
		internal.LogWhite("Supported Args:\n")
		flagSet.PrintDefaults()
		os.Exit(1)
	}
	if len(*kubiURL) == 0 {
		internal.LogRed("No kubiURL found, please add '--kubi-url https://<host,fqdn>:<port>' argument !")
		internal.LogWhite("Supported Args:\n")
		flagSet.PrintDefaults()
		os.Exit(1)
	}
	// Gathering CA for cluster in insecure mode
	if !strings.HasPrefix(*kubiURL, "https://") {
		*kubiURL = "https://" + *kubiURL
	}
	err := validation.Validate(&kubiURL, is.RequestURL)
	internal.ExitIfError(err)
	readPasswordIfEmpty(password)

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	if *useProxy {
		http.DefaultTransport.(*http.Transport).Proxy = http.ProxyFromEnvironment
	} else {
		http.DefaultTransport.(*http.Transport).Proxy = nil
	}
	internal.ExitIfError(err)

	caResp, err := http.DefaultClient.Get(*kubiURL + "/ca")
	internal.ExitIfError(err)
	body, err := ioutil.ReadAll(caResp.Body)
	internal.ExitIfError(err)
	ca := body

	base, _ := url.Parse(fmt.Sprintf("%v", *kubiURL))
	base.Path += "token"
	params := url.Values{
		"scopes": []string{*scopes},
	}
	base.RawQuery = params.Encode()
	wurl := base.String()

	req, err := http.NewRequest(http.MethodGet, wurl, nil)
	internal.ExitIfError(err)
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

		clusterName := strings.TrimPrefix(*kubiURL, "https://kubi.")
		username := fmt.Sprintf("%s_%s", *username, clusterName)

		kubeConfig.AuthInfos[kubeConfig.Contexts[username].AuthInfo].Token = string(tokenbody)
		err = clientcmd.WriteToFile(*kubeConfig, kubeconfigpath)
		internal.ExitIfError(err)
		internal.LogYellow("The token has successfully been rotated !")
		os.Exit(0)
	}

	internal.ExitIfError(err)
	fmt.Println(string(tokenbody))

}

func configCmd(flagSet *flag.FlagSet, kubiURL *string, username *string, password *string, insecure *bool, useProxy *bool) {
	if len(*username) == 0 {
		internal.LogRed("No username found, please add '--username <username>' argument !")
		internal.LogWhite("Supported Args:\n")
		flagSet.PrintDefaults()
		os.Exit(1)
	}
	if len(*kubiURL) == 0 {
		internal.LogRed("No kubiURL found, please add '--kubi-url https://<host,fqdn>:<port>' argument !")
		internal.LogWhite("Supported Args:\n")
		flagSet.PrintDefaults()
		os.Exit(1)
	}
	// Gathering CA for cluster in insecure mode
	if !strings.HasPrefix(*kubiURL, "https://") {
		*kubiURL = "https://" + *kubiURL
	}
	err := validation.Validate(&kubiURL, is.RequestURL)
	internal.ExitIfError(err)
	readPasswordIfEmpty(password)
	// Gathering CA for cluster in insecure mode
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	if *useProxy {
		http.DefaultTransport.(*http.Transport).Proxy = http.ProxyFromEnvironment
	} else {
		http.DefaultTransport.(*http.Transport).Proxy = nil
	}
	caResp, err := http.DefaultClient.Get(*kubiURL + "/ca")
	internal.ExitIfError(err)
	body, err := ioutil.ReadAll(caResp.Body)
	internal.ExitIfError(err)
	ca := body

	wurl := fmt.Sprintf("%v/config", *kubiURL)

	req, err := http.NewRequest(http.MethodGet, wurl, nil)
	internal.ExitIfError(err)
	if req == nil {
		internal.ExitIfError(errors.New("unexpected behaviour while forging request"))
	}
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
	currentUser, err := user.Current()
	internal.ExitIfError(err)

	kubeconfigpath, err := findKubeConfig()
	internal.ExitIfError(err)

	if !internal.FileExists(kubeconfigpath) {
		internal.LogNormal("Kubeconfig doesn't existing, it will be created.")
		err = os.MkdirAll(currentUser.HomeDir+"/.kube", 0600)
		internal.ExitIfError(err)
		f, err := os.Create(currentUser.HomeDir + "/.kube/config")
		internal.ExitIfError(err)
		err = f.Chmod(0600)
		internal.ExitIfError(err)

		newKubeConfig, err := clientcmd.Load(tokenbody)
		internal.ExitIfError(err)
		err = clientcmd.WriteToFile(*newKubeConfig, kubeconfigpath)
		internal.ExitIfError(err)

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

		err = clientcmd.WriteToFile(*existingKubeConfig, kubeconfigpath)
		internal.ExitIfError(err)
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

	kubiURL := commonFlags.String("kubi-url", internal.EmptyString, "Url to kubi server (ex: https://<kubi-ip>:<kubi-port>")
	insecure := commonFlags.Bool("insecure", false, "Skip TLS verification")
	username := commonFlags.String("username", internal.EmptyString, "Your username for connection")
	password := commonFlags.String("password", internal.EmptyString, "The password, use it at your own risks !")
	useProxy := commonFlags.Bool("use-proxy", false, "Use default proxy or not")

	scopes := tokenFlags.String("scopes", internal.EmptyString, "The token scope ( default user ). For promote, use 'promote'.")
	update := tokenFlags.Bool("update", false, "Update token directly in config")

	tokenFlags.AddFlagSet(commonFlags)
	configFlags.AddFlagSet(commonFlags)
	oldFlags.AddFlagSet(commonFlags)

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "explain":
			err := explainFlags.Parse(os.Args[2:])
			internal.ExitIfError(err)
			explainCmd(explainFlags)
		case "token":
			err := tokenFlags.Parse(os.Args[2:])
			internal.ExitIfError(err)
			tokenCmd(tokenFlags, kubiURL, username, password, insecure, useProxy, scopes, *update)

		case "config":
			err :=  configFlags.Parse(os.Args[2:])
			internal.ExitIfError(err)
			configCmd(configFlags, kubiURL, username, password, insecure, useProxy)

		case "version":
			err := versionFlags.Parse(os.Args[2:])
			internal.ExitIfError(err)
			internal.LogLightGray("1.8.6")
			os.Exit(0)
		default:
			generateConfig := oldFlags.Bool("generate-config", false, "Generate a config in ~/.kube/config")
			generateToken := oldFlags.Bool("generate-token", false, "Generate a token only")
			err := oldFlags.Parse(os.Args[1:])
			internal.ExitIfError(err)
			if *generateConfig {
				internal.LogReturn()
				internal.LogRed("Deprecated: Please use 'kubi config' instead of 'kubi --generate-config'")
				internal.LogReturn()

			}
			if *generateToken {
				configCmd(oldFlags, kubiURL, username, password, insecure, useProxy)
			} else if *generateConfig {
				configCmd(oldFlags, kubiURL, username, password, insecure, useProxy)
			} else {
				internal.LogReturn()
				internal.LogRed("\tThe usage of old command style is deprecated: please use kubi token, kubi config or kubi explain")
				internal.LogRed("\tYou should use --generate-token or --generate-config, for scopes, use only --scopes parameter\n")
				os.Exit(1)
			}
		}
	} else {
		internal.LogLightRed("\nNo argument specified, please read the documentation:")
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
