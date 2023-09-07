# SC4MP Server

A multiplayer gameserver for the PC videogame [SimCity 4](https://en.wikipedia.org/wiki/SimCity_4). Uses [python 3.8.10](https://www.python.org/downloads/release/python-3810/) and [py2exe](https://www.py2exe.org/). Built to work with the [SC4MP Client](https://github.com/kegsmr/sc4mp-client).


# Installation and Usage

Download the latest release and follow the instructions included in the Readme.html.


# Compiling

To compile the source code, run the setup.py script.


# API

This section is meant for developers using the server API. Here you can find examples of requests and responses from the server API, useful for creating a server scanner or client appplication for the SC4MP network.


## Add server

#### Request
> add_server \<port>

#### Response
none

## Check password

#### Request
> check_password \<password>

#### Response
> y

or

> n


## Password enabled

#### Request
> password_enabled

#### Response
> y

or

> n


## Ping

#### Request
> ping

#### Response
> pong


## Plugins

#### Request
> plugins

#### Response
TODO


## Private

#### Request
> private

#### Response
> y

or

> n


## Regions

#### Request
> regions

#### Response
TODO


## Save

#### Request
> save

#### Response
TODO


## Server description

#### Request
> server_description

#### Response
> \<server_description>


## Server ID

#### Request
> server_id

#### Response
> \<server_id>


## Server list

#### Request
> server_list

#### Response
> \<server 1 host> \<server 1 port> \<server 2 host> \<server 2 port> ... \<server n host> \<server n port>  


## Server name

#### Request
> server_name

#### Response
> \<server_name>


## Server URL

#### Request
> server_url

#### Response
> \<server_url>


## Server version

#### Request
> server_version

#### Response
> \<server_version as major.minor.patch>


## Time

#### Request
> time

#### Response
> \<time as %Y-%m-%d %H:%M:%S>


## Token

#### Request
> token

#### Response
TODO


## User ID

#### Request
> user_id

#### Response
TODO

## User plugins enabled

#### Request
> user_plugins_enabled

#### Response
> y

or

> n