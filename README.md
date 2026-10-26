# SC4MP Server

A multiplayer gameserver for the PC videogame [SimCity 4](https://en.wikipedia.org/wiki/SimCity_4). Uses [python 3.8.10](https://www.python.org/downloads/release/python-3810/), [pyinstaller](https://pyinstaller.org/) and [Inno Setup](https://jrsoftware.org/isinfo.php) script. Built to work with the [SC4MP Client](https://github.com/kegsmr/sc4mp-client).


# Installation

Download and run the installer from the [latest release](https://github.com/kegsmr/sc4mp-server/releases/latest).

Alternatively, use the [SC4MP Server Dockerizer](https://github.com/andreRBarata/sc4mp-server-docker) by [andreRBarata](https://github.com/andreRBarata) and deploy your server as a [Docker](https://www.docker.com/) container.


# Docker

The server can be run as a [Docker](https://www.docker.com/) container. An image is published to `ghcr.io/kegsmr/sc4mp-server` for each release, for `linux/amd64` and `linux/arm64`:

```sh
docker run -d -p 7240:7240 -v sc4mp:/data ghcr.io/kegsmr/sc4mp-server
```

The image is tagged with the version (e.g. `0.9.0`), the minor version (e.g. `0.9`) and `latest`. The `edge` tag is built from the `feature` branch, for testing.

The server directory (config, plugins, regions, databases and backups) is stored in the `/data` volume. Port `7240` must be reachable from the internet for players to connect.

To update, pull the new image and recreate the container. The server's own updater and system tray icon are not used in the container.

```sh
docker pull ghcr.io/kegsmr/sc4mp-server
docker rm -f <container>
docker run -d -p 7240:7240 -v sc4mp:/data ghcr.io/kegsmr/sc4mp-server
```

To build the image yourself instead, use the included `Dockerfile` and `docker-compose.yml`, which maps `/data` to `./data`:

```sh
docker compose up -d
```

For example, a private server with a password:

```yaml
services:
  sc4mp-server:
    image: ghcr.io/kegsmr/sc4mp-server
    ports:
      - "7240:7240"
    volumes:
      - ./data:/data
    environment:
      SC4MP_INFO_SERVER_NAME: "My Private Server"
      SC4MP_SECURITY_PASSWORD_ENABLED: "True"
      SC4MP_SECURITY_PASSWORD: "change-me"
    restart: unless-stopped
```

Any option in `serverconfig.ini` can be overridden with an environment variable named `SC4MP_<SECTION>_<OPTION>`, for example:

| Variable | Config option |
|----------|---------------|
| `SC4MP_NETWORK_PORT` | `[NETWORK] port` |
| `SC4MP_INFO_SERVER_NAME` | `[INFO] server_name` |
| `SC4MP_SECURITY_PASSWORD_ENABLED` | `[SECURITY] password_enabled` |
| `SC4MP_SECURITY_PASSWORD` | `[SECURITY] password` |
| `SC4MP_RULES_CLAIM_DURATION` | `[RULES] claim_duration` |

Environment variables take priority over `serverconfig.ini` and are not written to it. If you change the port, map the same port in `docker-compose.yml` (e.g. `"7241:7241"`) so the server's announced port matches.


# Usage

Follow the instructions included in the `Readme.html` file.


# Compiling

To compile the source code, run the `setup.py` script.


# Protocol

This section is meant for developers using the SC4MP protocol. Here you can find examples of requests and responses from the server, useful for creating a server scanner or client appplication for the SC4MP network.

The SC4MP protocol is a lightweight, binary-framed JSON-based protocol designed for reliable TCP communication between SC4MP clients and servers. All messages begin with a **16-byte fixed header** followed by a variable-length JSON payload.

Communication uses **request-response** semantics — every client request expects a corresponding server response with the same command code.


---

## Message Structure

| Section | Size | Description |
|----------|------|-------------|
| Protocol Identifier | 5 bytes | Always `"SC4MP"` |
| Message Type | 3 bytes | `"Req"` for requests, `"Res"` for responses |
| Command Code | 6 bytes | ASCII command name, null-padded |
| Header Length | 2 bytes | Unsigned short (`H`), specifies length of JSON payload |
| Headers | Variable | UTF-8 JSON-encoded key-value pairs |


---

## Commands

### COMMAND_ADD_SERVER (`AddSrv`)
Adds the requesting server to another server’s list.

**Request:**
```json
{"host": "<hostname>", "port": <port>}
```

**Response:**
```json
{"status": "success"}
```

---

### COMMAND_CHECK_PASSWORD (`ChkPwd`)
Verifies a server password.

**Request:**
```json
{"password": "<password>"}
```

**Response:**
```json
{"status": "success"}  // or {"status": "failure"}
```

---

### COMMAND_INFO (`Info`)
Retrieves general server information.

**Request:**
```json
{}
```

**Response:**
```json
{
  "server_id": "<string>",
  "server_name": "<string>",
  "server_description": "<string>",
  "server_url": "<string>",
  "server_version": "<string>",
  "private": <bool>,
  "password_enabled": <bool>,
  "user_plugins_enabled": <bool>
}
```

---

### COMMAND_PASSWORD_ENABLED (`PwdEnb`)
Checks if the server requires a password.

**Response:**
```json
{"password_enabled": true}
```

---

### COMMAND_PING (`Ping`)
Verifies connectivity.

**Response:**
```json
{}
```

---

### COMMAND_PLUGINS_TABLE (`PlgTbl`)
Retrieves a list of available plugin files.

**Response:**
```json
[
  ["<md5>", <filesize>, "<relative_path>"],
  ...
]
```

---

### COMMAND_PLUGINS_DATA (`PlgDat`)
Requests actual plugin data after receiving a plugin table.

**Request:**
```json
[
  ["<md5>", <filesize>, "<relative_path>"],
  ...
]
```

**Response:**
Raw file data stream matching the table entries.

---

### COMMAND_PRIVATE (`Prv`)
Indicates whether plugin and region access requires authentication.

**Response:**
```json
{"private": true}
```

---

### COMMAND_REGIONS_TABLE (`RgnTbl`)
Retrieves a list of available region files.

**Response:**
```json
[
  ["<md5>", <filesize>, "<relative_path>"],
  ...
]
```

---

### COMMAND_REGIONS_DATA (`RgnDat`)
Requests actual region data after receiving a region table.

**Request:**
```json
[
  ["<md5>", <filesize>, "<relative_path>"],
  ...
]
```

**Response:**
Raw file data stream matching the table entries.

---

### COMMAND_SAVE (`Save`)
Pushes a region save to the server.

**Sequence:**
1. Request with version and user authentication headers.
2. Send file table JSON array.
3. Send raw file data.
4. Server responds with:
```json
{"result": "ok"}
```

---

### COMMAND_SERVER_LIST (`SrvLst`)
Retrieves the global SC4MP server list.

**Response:**
```json
[
  ["<host1>", <port1>],
  ["<host2>", <port2>],
  ...
]
```

---

### COMMAND_USER_ID (`UserId`)
Validates user identity by checking a hashed token.

**Request:**
```json
{"hash": "<sha256(user_id + token)>"} 
```

**Response:**
```json
{"user_id": "<uuid>"}
```

---

### COMMAND_TOKEN (`Token`)
Requests a random token for authentication.

**Request:**
```json
{"user_id": "<uuid>"}
```

**Response:**
```json
{"token": "<random_string>"}
```

---

### COMMAND_TIME (`Time`)
Retrieves the current server time.

**Response:**
```json
{"time": "YYYY-MM-DD HH:MM:SS"}
```

---

### COMMAND_LOADING_BACKGROUND (`LdgBkg`)
Retrieves the loading background image data.

**Response:**
```json
{"size": <integer>}
```
Followed by a binary payload of `<size>` bytes.

---
