# Kubi Client

Kubi-cli is a Kubernetes IAM authentication client aloow you to consume
securely ( eg: without skipping tls verification) Kubi token.

## Usage

You can simple call `kubi` with `-h` parameter.
```bash
./kubi -h
```
**Parameters:**
```bash
--generate-config # Generate the config file in ~/.kube/config
--kubi-url https://<kubi server ip,url>:<kubi server port> # Kubi Server Url
--username <your_username> #The CN attribute ( not LDAP DN !)
```
## Install
**Linux & Mac**
```bash
# binary will be $(go env GOPATH)/bin/kubi
curl -sSfL https://raw.githubusercontent.com/ca-gip/kubi-cli/master/install.sh | sh -s -- -b $(go env GOPATH)/bin 

# or /usr/local/bin/kubi (sudoers required)
curl -sSfL https://raw.githubusercontent.com/ca-gip/kubi-cli/master/install.sh | sudo sh -s -- -b /usr/local/bin

kubi version
```

**Windows**

Execute this command using *Git bash* for windows.
```bash
# binary will be $(go env GOPATH)/bin/kubi
curl -sSfL https://raw.githubusercontent.com/ca-gip/kubi-cli/master/install.sh | sh -s -- -b $(go env GOPATH)/bin 

kubi version
```
