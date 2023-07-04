# Kubi Client

Kubi-cli is a Kubernetes IAM authentication client aloow you to consume
securely ( eg: without skipping tls verification) Kubi token.

# Versioning
Since version v1.24.0, we have decided to modify the naming of versions for ease of reading and understanding.

Example: v1.24.0 means that the operator was developed for Kubernetes version 1.24 and that the last 0 corresponds to the various patches we have made to the operator.

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
