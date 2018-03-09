# Hikari-go
The Golang version of Hikari

### About
Hikari, A network proxy tool which helps you break through network restrictions.

How it works:

```
Local
<---[SOCKS5 or HTTP protocol over local machine]--->
Hikari client
<---[Hikari protocol(encrypted) over Internet]--->
Hikari server
<---[Local data]--->
Target
```

### Usage
Client side:
> ./hikari-client-xx-xxx client.json

Server side:
> ./hikari-server-xx-xxx server.json

### Sample configuration
Client side:

```
{
  "listenAddress": "localhost", // local SOCKS5 and HTTP proxy server address
  "listenPort": 1180, // associated port
  "serverAddress": "localhost", // Hikari server address
  "serverPort": 9670, // associated port
  "privateKey": "hikari", // authentication key, must be same with server side
  "secret": "hikari-secret" // encryption key, must be same with server side
}
```

Server side:

```
{
  "listenAddress": "localhost", // Hikari server address
  "listenPort": 9670, // associated port
  "privateKeyList": [ // authentication key list
    "hikari"
  ],
  "secret": "hikari-secret" // encryption key
}
```
