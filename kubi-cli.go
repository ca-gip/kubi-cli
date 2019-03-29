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
	"gopkg.in/yaml.v2"
	"fmt"
	"encoding/base64"
	"encoding/json"
)

func check(e error) {
	if e != nil {
		fmt.Println(e)
		os.Exit(1)
	}
}

type Conf struct {
	APIVersion string `json:"apiVersion"`
	Clusters   []struct {
		Cluster struct {
			CertificateAuthorityData string `json:"certificate-authority-data"`
			Server                   string `json:"server"`
		} `json:"cluster"`
		Name string `json:"name"`
	} `json:"clusters"`
	Contexts []struct {
		Context struct {
			Cluster   string `json:"cluster"`
			Namespace string `json:"namespace"`
			User      string `json:"user"`
		} `json:"context"`
		Name string `json:"name"`
	} `json:"contexts"`
	CurrentContext string `json:"current-context"`
	Kind           string `json:"kind"`
	Preferences    struct {
	} `json:"preferences"`
	Users []struct {
		Name string `json:"name"`
		User struct {
			Token string `json:"token"`
		} `json:"user"`
	} `json:"users"`
}

type JWT_rights struct {
	Auths []struct {
		Namespace string `json:"namespace"`
		Role      string `json:"role"`
	} `json:"auths"`
	User        string `json:"user"`
	AdminAccess bool   `json:"adminAccess"`
	Exp         int    `json:"exp"`
	Iss         string `json:"iss"`
}

func unmarshal_config (path string) Conf {
	confYaml, err := ioutil.ReadFile(path)
	var config Conf
	err = yaml.Unmarshal(confYaml, &config)
	if err != nil {
		panic(err)
	}
	return config
}

func main() {

	kubiUrl := flag.String("kubi-url", "", "Url to kubi server (ex: https://<kubi-ip>:<kubi-port>")
	generateConfig := flag.Bool("generate-config", false, "Generate a config in ~/.kube/config")
	generateToken := flag.Bool("generate-token", true, "Generate a token only")
	insecure := flag.Bool("insecure", false, "Skip TLS verification")
	username := flag.String("username", "", "Ldap username ( not dn )")
	useProxy := flag.Bool("use-proxy", false, "Use default proxy or not")
	flag.Parse()

	user, err := user.Current()
	check(err)
	if len(os.Args)>1 {
		switch os.Args[1] {
			case "get-config":
				config := unmarshal_config(user.HomeDir + "/.kube/config")
				b64_token := strings.Split(config.Users[0].User.Token,".")[1]
				//Add the base64 padding
				l := len(b64_token)%4
				if l%4 > 0 {
					b64_token += strings.Repeat("=", 4-l)
				}
				data, err := base64.StdEncoding.DecodeString(b64_token)				
				var jwt JWT_rights
				err = json.Unmarshal(data, &jwt)
				if err != nil {
					panic(err)
				}
				var namespaces string
				for i := 0; i < len(jwt.Auths); i++ {
					namespaces +=  jwt.Auths[i].Namespace + "\n"
				}
				fmt.Println("User\n----\n"+config.Users[0].Name+"\n\nCluster\n-------\n"+config.Clusters[0].Cluster.Server+"\n\nNamespaces\n----------\n"+namespaces)
				os.Exit(1)
			default:
				fmt.Println("Unkwown command.")
				os.Exit(1)
		}
	}

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
	err = validation.Validate(&kubiUrl, is.RequestURL)
	check(err)

	fmt.Print("Enter your Ldap password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	check(err)

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

	url := *kubiUrl + "/config"
	if *generateToken {
		url = *kubiUrl + "/token"
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	req.SetBasicAuth(*username, string(bytePassword))

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

	if *generateConfig {
		os.MkdirAll(user.HomeDir+"/.kube", 0600)
		f, err := os.Create(user.HomeDir + "/.kube/config")
		check(err)
		f.Write(tokenbody)
		f.Chmod(0600)
		f.Close()
		fmt.Printf("Great ! Your config has been saved in %s\n", f.Name())
	} else if *generateToken {
		fmt.Println(string(tokenbody))
	} else {
		fmt.Println("\n\nGreat ! You can use --generate-config to directly save it in ~/.kube/config next time ! \n\n")
		fmt.Println(string(tokenbody))
	}
}
