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
