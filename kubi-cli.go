package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"strings"
	"syscall"
	"time"
	"github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
)

func check(e error) {
	if e != nil {
		fmt.Println(e)
		os.Exit(1)
	}
}

type Conf struct {
	APIVersion string `yaml:"apiVersion"`
	Clusters   []struct {
		Cluster struct {
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			Server                   string `yaml:"server"`
		} `yaml:"cluster"`
		Name string `yaml:"name"`
	} `yaml:"clusters"`
	Contexts []struct {
		Context struct {
			Cluster   string `yaml:"cluster"`
			Namespace string `yaml:"namespace"`
			User      string `yaml:"user"`
		} `yaml:"context"`
		Name string `yaml:"name"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
	Kind           string `yaml:"kind"`
	Preferences    struct {
	} `yaml:"preferences"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token string `yaml:"token"`
		} `yaml:"user"`
	} `yaml:"users"`
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
	check(err)
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

			//Decode the JWT base64 token
			b64_token := strings.Split(config.Users[0].User.Token, ".")[1]
			//Add the base64 padding
			l := len(b64_token)%4
			if l%4 > 0 {
				b64_token += strings.Repeat("=", 4-l)
			}
			data, err := base64.StdEncoding.DecodeString(b64_token)
			var jwt JWT_rights
			err = json.Unmarshal(data, &jwt)
			check(err)

			//Get the expiracy date
			var expires_int int64
			expires_int = int64(jwt.Exp)
			unixTimeUTC := time.Unix(expires_int, 0)
			expires := unixTimeUTC.Format(time.RFC3339)

			//Get the current context user and cluster details
			var user string
			var cluster string
			for i := range config.Contexts {
				if config.Contexts[i].Name == config.CurrentContext {
					user = config.Contexts[i].Context.User
					cluster = strings.Split(config.Contexts[i].Name, "-")[0]
					break
				}
			}
			var cluster_url string
			for i := range config.Clusters {
				if config.Clusters[i].Name == cluster {
					cluster_url = config.Clusters[i].Cluster.Server
					cluster_url = cluster_url[strings.Index( cluster_url, "." )+1:len(cluster_url)]
					break
				}
			}
			var token string
			var namespaces string
			for i := range config.Users {
				if config.Users[i].Name == user {
					token = config.Users[i].User.Token

					//Decode the JWT base64 token
					b64_token := strings.Split(token, ".")[1]
					//Add the base64 padding
					l := len(b64_token)%4
					if l%4 > 0 {
						b64_token += strings.Repeat("=", 4-l)
					}
					data, err := base64.StdEncoding.DecodeString(b64_token)
					var jwt JWT_rights
					err = json.Unmarshal(data, &jwt)
					check(err)

					//List the namespaces from the JWT token
					for i := 0; i < len(jwt.Auths); i++ {
						namespaces += jwt.Auths[i].Namespace + "\n"
					}
					break
				}
			}

			//Print the result
			fmt.Println("User\n----\n" + user + "\n\nCluster\n-------\n" + cluster_url + "\n\nNamespaces\n----------\n" + namespaces + "\n\nExpires\n-------\n" + expires)
			os.Exit(1)
		default:
			fmt.Println("Unkwown command.")
			os.Exit(1)
		}
	
	//Default connexion command
	} else if len(os.Args) == 0 {
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
}
