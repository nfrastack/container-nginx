# nfrastack/container-nginx
# WIP BETA 8
## About

This will build a container for [Nginx](https://www.nginx.org), for serving websites or proxying data.

*    Tracks Mainline release channel

*    Many server options configurable including compression, performance, status reporting
*    Individual site configuration for HTTP, HTTPS, HTTP2, HTTP3 serving with hardening, logging and other options
*    Ability to Password Protect (Basic), LDAP Authenticatione or use LemonLDAP:NG Handler
*    Includes [Nginx Ultimate Bad Bot Blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker)

## Maintainer

- [Nfrastack](https://www.nfrastack.com)

## Table of Contents

- [About](#about)
- [Maintainer](#maintainer)
- [Installation](#installation)
  - [Prebuilt Images](#prebuilt-images)
  - [Quick Start](#quick-start)
  - [Persistent Storage](#persistent-storage)
- [Configuration](#configuration)
  - [Quick Start](#quick-start)
  - [Persistent Storage](#persistent-storage)
  - [Environment Variables](#environment-variables)
    - [Base Images used](#base-images-used)
    - [Container Options](#container-options)
      - [Server Configuration](#server-configuration)
      - [Performance Options](#performance-options)
      - [Reverse Proxy Options](#reverse-proxy-options)
      - [TLS Options](#tls-options)
      - [Bot Blocking Options](#bot-blocking-options)
      - [Compression Options](#compression-options)
      - [DDoS Options](#ddos-options)
      - [Include Options](#include-options)
    - [Site Configuration](#site-configuration)
      - [Site Mode & Per-Site Options](#site-mode--per-site-options)
      - [Authentication Options](#authentication-options)
      - [Header Options](#header-options)
      - [Logging Options](#logging-options)
      - [Client Cache Configuration](#client-cache-configuration)
      - [Custom Parameters](#custom-parameters)
      - [Maintenance Options](#maintenance-options)
      - [MTLS Options (WIP)](#mtls-options-wip)
- [Users and Groups](#users-and-groups)
- [Networking](#networking)
- [Maintenance](#maintenance)
  - [Shell Access](#shell-access)
- [Support & Maintenance](#support--maintenance)
- [References](#references)
- [License](#license)

## Installation

### Prebuilt Images
Feature limited builds of the image are available on the [Github Container Registry](https://github.com/nfrastack/container-nginx/pkgs/container/container-nginx) and [Docker Hub](https://hub.docker.com/r/nfrastack/nginx).

To unlock advanced features, one must provide a code to be able to change specific environment variables from defaults. Support the development to gain access to a code.

To get access to the image use your container orchestrator to pull from the following locations:

```
ghcr.io/nfrastack/container-nginx:(image_tag)
docker.io/nfrastack/nginx:(image_tag)
```

The following image tags are available along with their tagged release based on what's written in the [Changelog](CHANGELOG.md):

| Alpine Base | Tag            | Debian Base | Tag                |
| ----------- | -------------- | ----------- | ------------------ |
| latest      | `:latest`      | latest      | `:debian`          |
| latest      | `:alpine`      | Trixie      | `:debian_trixie`   |
| edge        | `:alpine_edge` | Bookworm    | `:debian_bookworm` |
| 3.23        | `:alpine_3.23` |             |                    |
| 3.22        | `:alpine_3.22` |             |                    |
| 3.19        | `:alpine_3.19` |             |                    |
| 3.16        | `:alpine_3.16` |             |                    |
| 3.15        | `:alpine_3.15` |             |                    |
| 3.12        | `:alpine_3.12` |             |                    |

Image tag syntax is:

`<image>:<optional tag>-<optional_distribution>_<optional_distribution_variant>`

Example:

`ghcr.io/nfrastack/container-nginx:latest` or

`ghcr.io/nfrastack/container-nginx:1.0` or

`ghcr.io/nfrastack/container-nginx:1.0-alpine` or

`ghcr.io/nfrastack/container-nginx:alpine` or

`ghcr.io/nfrastack/container-nginx:alpine_3.23`

* `latest` will be the most recent commit
* An optional `tag` may exist that matches the [CHANGELOG](CHANGELOG.md) - These are the safest
* If it is built for multiple distributions there may exist a value of `alpine` or `debian`
* If there are multiple distribution variations it may include a version - see the registry for availability

Have a look at the container registries and see what tags are available.

#### Multi-Architecture Support

Images are built for `amd64` by default, with optional support for `arm64` and other architectures.

## Configuration

### Quick Start

* The quickest way to get started is using [docker-compose](https://docs.docker.com/compose/). See the examples folder for a working [compose.yml](examples/compose.yml) that can be modified for your use.

* Map [persistent storage](#persistent-storage) for access to configuration and data files for backup.
* Set various [environment variables](#environment-variables) to understand the capabilities of this image.
* Make [networking ports](#networking) available for public access if necessary

The container starts up and reads from the nginx server "${NGINX_CONFIG_PATH}/${NGINX_CONFIG_FILE}` (typically /etc/nginx/server.conf) for server cconfiguration. It creates a sub folder called `/etc/nginx/server.conf.d` that creates files to support server configuration based on the values of the environment variables.

If you do not set `NGINX_SITE_ENABLED` a default site will be created for you and the appropriate settings will be created inside of `/etc/nginx/sites.enabled/default.conf` which will import various site configuration fragments based on environment variables.

### Persistent Storage

The following directories are used for configuration and can be mapped for persistent storage.

| Directory     | Description                                           |
| ------------- | ----------------------------------------------------- |
| `/www/html`   | Drop your web source files here to be served by Nginx |
| `/logs/nginx` | Logfiles for Nginx error and Access                   |

### Custom Site Configuration

If you want to add custom configuration to any of the files, create a folder in `(/container/data/nginx/ or /etc/nginx/) sites.available/<fragment>` and place a file with the extension of `.conf` to have it parsed. See site configuration fragment sectiont to understand further.

| `<fragment>`     | Description                                   |
| ---------------- | --------------------------------------------- |
| `location/`      | main Location Blocks                          |
| `location-pre/`  | Before main Location Blocks                   |
| `location-post/` | After main Location Blocks                    |
| `server-pre/`    | Before site server block                      |
| `server-begin/`  | Start of the site server block                |
| `server-end/`    | Right before the end of the site server block |
| `server-post/`   | After site server block                       |

>> Files get parsed numerically (0-9) and alphabetically (a-z)

#### Example 1

`/etc/nginx/sites.available/default/location/01-images.conf`

```bash
location /images/ {
    root /var/www/media;
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}
```

#### Example 2

`/etc/nginx/sites.available/default/location/assets.conf`

```bash
location ~* \.(css|js)$ {
    alias /var/www/assets/;
    expires 30d;
    add_header Cache-Control "public";
}
```

#### Example 3

`/etc/nginx/sites.available/default/server-pre/80-header_test.conf`

```bash
add_head test_header "site_wide"
```

### Environment Variables

#### Base Images used

This image relies on a customized base image in order to work.
Be sure to view the following repositories to understand all the customizable options:

| Image                                                   | Description |
| ------------------------------------------------------- | ----------- |
| [OS Base](https://github.com/nfrastack/container-base/) | Base Image  |

Below is the complete list of available options that can be used to customize your installation.

* Variables showing an 'x' under the `Advanced` column can only be set if the containers advanced functionality is enabled.

#### Server Configuration

##### Container Options

| Parameter                                | Description                                                                   | Default                     | Site | Advanced |
| ---------------------------------------- | ----------------------------------------------------------------------------- | --------------------------- | ---- | -------- |
| `NGINX_USER`                             | What user to run nginx as inside container                                    | `nginx`                     |      |          |
| `NGINX_GROUP`                            | What group to run nginx as inside container                                   | `www-data`                  |      |          |
| `NGINX_SITE_ENABLED`                     | What sites to enable in `/etc/nginx/sites.available` Don't use `.conf` suffix | `ALL`                       |      |          |
| `NGINX_CONFIG_PATH`                      | Nginx config base path inside container                                       | `/etc/nginx/`               |      |          |
| `NGINX_CONFIG_FILE`                      | Primary nginx config filename                                                 | `server.conf`               |      |          |
| `NGINX_WORKER_PROCESSES`                 | How many processes to spawn                                                   | `1`                         |      |          |
| `NGINX_WORKER_CONNECTIONS`               | Determines how much clients will be served per worker                         | `1024`                      |      | x        |
| `NGINX_MIME_TYPES_PATH`                  | Path where mime types are written                                             | `${NGINX_CONFIG_PATH%/}/`   |      | x        |
|                                          |                                                                               | `${NGINX_CONFIG_FILE%/}.d/` |      | x        |
| `NGINX_MIME_TYPES_FILE`                  | Mime types filename                                                           | `mime_types.conf`                |      |          |
| `NGINX_ENABLE_APPLICATION_CONFIGURATION` | Don't automatically setup /etc/nginx/sites.available files                    |                             |      |          |
|                                          | Useful for volume mapping/overriding                                          | `TRUE`                      | x    |          |
| `NGINX_ENABLE_METRICS`                   | Enable monitoring endpoint on port 127.0.0.1:73                               | `TRUE`                      |      |          |
| `NGINX_RELOAD_ON_CONFIG_CHANGE`          | Automatically reload nginx on configuration file change                       | `FALSE`                     |      |          |
| `NGINX_POST_INIT_SCRIPT`                 | If you wish to run a bash script before the nginx process runs                |                             |      |          |
|                                          | enter the path here, seperate multiple by commas.                             |                             |      |          |

##### Performance Options

| Parameter                                | Description                                                                             | Default  | Advanced |
| ---------------------------------------- | --------------------------------------------------------------------------------------- | -------- | -------- |
| `NGINX_CACHE_OPEN_FILE_ERRORS`           | Cache errors like 404                                                                   | `TRUE`   | x        |
| `NGINX_CACHE_OPEN_FILE_INACTIVE`         | Stop caching after inactive                                                             | `5m`     | x        |
| `NGINX_CACHE_OPEN_FILE_MAX`              | Maximum files to cache                                                                  | `200000` | x        |
| `NGINX_CACHE_OPEN_FILE_MIN_USES`         | Minimum uses of file before cashing                                                     | `2`      | x        |
| `NGINX_CACHE_OPEN_FILE_VALID`            | Cache a file if has been accessed within this window                                    | `2m`     | x        |
| `NGINX_CLIENT_BODY_BUFFER_SIZE`          | Client Buffer size                                                                      | `16k`    | x        |
| `NGINX_CLIENT_BODY_TIMEOUT`              | Request time out                                                                        | `60`     | x        |
| `NGINX_ENABLE_EPOLL`                     | Optmized to serve many clients with each thread, essential for linux                    | `TRUE`   |          |
| `NGINX_ENABLE_MULTI_ACCEPT`              | Accept as many connections as possible, may flood worker connections if set too low     | `TRUE`   |          |
| `NGINX_ENABLE_OPEN_FILE_CACHE`           | Cache informations about FDs, frequently accessed files                                 | `TRUE`   |          |
| `NGINX_ENABLE_PCRE_JIT`                  | Enable PCRE JIT for regex speedups                                                      | `TRUE`   |          |
| `NGINX_ENABLE_PROXY_BUFFERING`           | Enable Proxy Buffering                                                                  | `TRUE`   |          |
| `NGINX_ENABLE_RESET_TIMEDOUT_CONNECTION` | Allow the server to close connection on non responding client, this will free up memory | `TRUE`   |          |
| `NGINX_ENABLE_SENDFILE`                  | Copies data between one FD and other from within the kernel                             | `TRUE`   |          |
| `NGINX_ENABLE_SERVER_TOKENS`             | Show Nginx version on responses                                                         | `FALSE`  |          |
| `NGINX_ENABLE_TCPNODELAY`                | Don't buffer data sent, good for small data bursts in real time                         | `TRUE`   |          |
| `NGINX_ENABLE_TCPNOPUSH`                 | Send headers in one peace, its better then sending them one by one                      | `TRUE`   |          |
| `NGINX_ENABLE_UPSTREAM_KEEPALIVE`        | Reuse connections when using upstream (LLNG Auth, FastCGI etc)                          | `TRUE`   |          |
| `NGINX_FASTCGI_BUFFER_SIZE`              | FastCGI Buffer Size                                                                     | `32k`    | x        |
| `NGINX_FASTCGI_BUFFERS`                  | Amount of FastCGI Buffers                                                               | `16 16k` | x        |
| `NGINX_KEEPALIVE_REQUESTS`               | Number of requests client can make over keep-alive                                      | `100000` | x        |
| `NGINX_KEEPALIVE_TIMEOUT`                | Server will close connection after this time                                            | `75`     | x        |
| `NGINX_PROXY_BUFFER_SIZE`                | Proxy Buffer Size                                                                       | `128k`   | x        |
| `NGINX_PROXY_BUFFERS`                    | Proxy Buffers                                                                           | `4 256k` | x        |
| `NGINX_PROXY_BUSY_BUFFERS_SIZE`          | Proxy Busy Buffers Size                                                                 | `256k`   | x        |
| `NGINX_PROXY_HEADERS_BUCKET_SIZE`        | Proxy Headers Bucket Size                                                               | `128`    | x        |
| `NGINX_PROXY_HEADERS_HASH_MAX_SIZE`      | Proxy Headers Max Size                                                                  | `1024`   | x        |
| `NGINX_RESOLVER`                         | Resolve hostnames via DNS. Space seperated values. e.g. `127.0.0.11`                    |          |          |
| `NGINX_SEND_TIMEOUT`                     | If client stop responding, free up memory                                               | `60`     | x        |
| `NGINX_SERVER_NAMES_HASH_BUCKET_SIZE`    | Server names hash size (`256`` if `NGINX_ENABLE_BLOCK_BOTS=TRUE`)                       | `32`     | x        |
| `NGINX_UPLOAD_MAX_SIZE`                  | Maximum Upload Size                                                                     | `2G`     |          |
| `NGINX_UPSTREAM_KEEPALIVE`               | Keepalive connections to utilize for upstream                                           | `32`     | x        |
| `NGINX_WORKER_RLIMIT_NOFILE`             | Number of file descriptors used for nginx                                               | `100000` | x        |

##### Reverse Proxy Options

| Parameter                    | Description                                                       | Default           | Advanced |
| ---------------------------- | ----------------------------------------------------------------- | ----------------- | -------- |
| `NGINX_ENABLE_REVERSE_PROXY` | Helpers for when behind a reverse proxy                           | `TRUE`            |          |
| `NGINX_REAL_IP_HEADER`       | What is the header passed containing the visitors IP              | `X-Forwarded-For` |          |
| `NGINX_SET_REAL_IP_FROM`     | Set the network of your Docker Network if having IP lookup issues | `172.16.0.0/12`   |          |

##### TLS Options

| Parameter                         | Description                                                    | Default                                                       | Site | Advanced |
| --------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------- | ---- | -------- |
| `NGINX_TLS_ECDH_CURVE`            | ECDH curves to use for TLS key exchange                        | `X25519:prime256v1:secp384r1`                                 |      | x        |
| `NGINX_TLS_PROTOCOLS`             | TLS protocol versions to enable (e.g. `TLSv1.3 TLSv1.2`)       | `TLSv1.3`                                                     |      |          |
| `NGINX_TLS_PREFER_SERVER_CIPHERS` | Prefer server cipher order over client preference              | `FALSE`                                                       |      | x        |
| `                                 |                                                                |                                                               |      |
| `NGINX_TLS_CIPHERS`               | (<1.3) Ciphers to utilize                                      | `ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256`   |      | x        |
|                                   |                                                                | `:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:` |      |          |
|                                   |                                                                | `ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:`  |      |          |
|                                   |                                                                | `DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:`        |      |          |
|                                   |                                                                | `DHE-RSA-CHACHA20-POLY1305`                                   |      |          |
| `NGINX_TLS_SESSION_TIMEOUT`       | (<1.3) TLS session timeout duration                            | `1d`                                                          |      | x        |
| `NGINX_TLS_SESSION_CACHE`         | (<1.3) TLS session cache settings                              | `shared:SSL:10m`                                              |      | x        |
| `NGINX_TLS_DH_PARAM_FILE`         | (<1.3) Path to DH parameter file eg `/certs/nginx/dhparam.pem` |                                                               |      | x        |
| `NGINX_TLS_CREATE_SELFSIGNED`     | Auto-generate self-signed cert when missing                    | `TRUE`                                                        | x    |

##### Bot Blocking Options

For more details on how Bot Blocking works please visit Nginx Ultimate Bad Bot Blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker)

| Parameter                            | Description                                                      | Default                              | Advanced |
| ------------------------------------ | ---------------------------------------------------------------- | ------------------------------------ | -------- |
| `NGINX_ENABLE_BLOCK_BOTS`            | Block Bots and Crawlers                                          | `FALSE`                              |          |
| `NGINX_BLOCKBOTS_CONFIG_CUSTOM_PATH` | Path for custom botblocker files                                 | `${CONFIG_PATH%/}/blockbots-custom/` |          |
| `NGINX_BLOCK_BOTS_WHITELIST_DOMAIN`  | Domains to whitelist from blocking comma seperated               |                                      |          |
|                                      | e.g. `example1.com,example2.com`                                 |                                      |          |
| `NGINX_BLOCK_BOTS_WHITELIST_IP`      | IP Addresses/Networks to Whitelist from Blocking comma seperated | `127.0.0.1,10.0.0.0/8,`              | x        |
|                                      |                                                                  | `172.16.0.0/12,192.168.0.0/24`       |          |
| `NGINX_BLOCK_BOTS`                   | Bots to Block                                                    |                                      |          |
|                                      | `ALL` `AOL` `BING` `DOCOMO` `DUCKDUCKGO`                         |                                      |          |
|                                      | `FACEBOOK` `GOOGLE` `LINKEDIN` `MISC` `MSN`                      |                                      |          |
|                                      | `SAMSUNG` `SLACK` `SLURP` `TWITTER` `WORDPRESS`                  |                                      |          |
|                                      | `YAHOO` or `yourcustom-useragent` in Comma Seperated values      |                                      |          |


##### Compression Options

| Parameter                             | Description                                  | Default                                     | Advanced |
| ------------------------------------- | -------------------------------------------- | ------------------------------------------- | -------- |
| `NGINX_ENABLE_COMPRESSION_BROTLI`     | Enable Brotli Compression                    | `TRUE`                                      |          |
| `NGINX_COMPRESSION_BROTLI_LEVEL`      | Compression Level for Brotli                 | `6`                                         | x        |
| `NGINX_COMPRESSION_BROTLI_MIN_LENGTH` | Minimum length of content before compressing | `20`                                        | x        |
| `NGINX_COMPRESSION_BROTLI_TYPES`      | What filetypes to compress                   | `text/plain text/css text/xml`              | x        |
|                                       |                                              | `text/javascript application/x-javascript`  |          |
|                                       |                                              | `application/json application/xml`          |          |
| `NGINX_COMPRESSION_BROTLI_WINDOW`     |                                              | `512k`                                      | x        |
| `NGINX_ENABLE_COMPRESSION_GZIP`       | Enable GZIP Compression                      | `TRUE`                                      |          |
| `NGINX_COMPRESSION_GZIP_BUFFERS`      |                                              | `16 8k`                                     | x        |
| `NGINX_COMPRESSION_GZIP_DISABLE`      | Don't compress for these user agents         | `MSIE [1-6].(?!.*SV1)`                      | x        |
| `NGINX_COMPRESSION_GZIP_HTTP_VERSION` |                                              | `1.1`                                       | x        |
| `NGINX_COMPRESSION_GZIP_LEVEL`        | Compression Level                            | `6`                                         | x        |
| `NGINX_COMPRESSION_GZIP_MIN_LENGTH`   | Minimum length of content before compressing | `10240`                                     | x        |
| `NGINX_COMPRESSION_GZIP_PROXIED`      |                                              | `expired no-cache no-store private auth`    | x        |
| `NGINX_COMPRESSION_GZIP_TYPES`        | Types of content to compress                 | `text/plain text/css`                       | x        |
|                                       |                                              | `text/xml text/javascript`                  |          |
|                                       |                                              | `application/x-javascript application/json` |          |
|                                       |                                              | `application/xml`                           |          |
| `NGINX_COMPRESSION_GZIP_VARY`         |                                              | `TRUE`                                      | x        |

##### DDoS Options

| Parameter                       | Description                        | Default | Advanced |
| ------------------------------- | ---------------------------------- | ------- | -------- |
| `NGINX_ENABLE_DDOS_PROTECTION`  | Enable simple DDoS Protection      | `FALSE` |          |
| `NGINX_DDOS_CONNECTIONS_PER_IP` | Limit amount of connections per IP | `10m`   | x        |
| `NGINX_DDOS_REQUESTS_PER_IP`    | Limit amount of requests per IP    | `5r/s`  | x        |


##### Include Options

You can inject include files into specific places of the server configuration using environment variables. The container symlinks each listed path into the server fragment folder. Source files must exist and be readable inside the container at startup.

| Environment Variable                            | Description                                |
| ----------------------------------------------- | ------------------------------------------ |
| `NGINX_SERVER_INCLUDE_CONFIGURATION_<FRAGMENT>` | Comma-separated absolute paths to include. |

###### FRAGMENT Values:

| `<FRAGMENT>`   | Destination folder (inside `${NGINX_CONFIG_PATH%/}/sites.enabled/<sitename>/`) |
| -------------- | ------------------------------------------------------------------------------ |
| `ROOT`         | `/` `${NGINX_CONFIG_PATH%/}/%{NGINX_CONFIG_FILE}.d` Main file                  |
| `EVENTS`       | `events/` Events block                                                         |
| `HTTP`         | `http/` HTTP Blocks                                                            |
| `SERVER_PRE`   | `server-pre/` Before site server block                                         |
| `SERVER_BEGIN` | `server-begin/` Start of the site server block                                 |
| `SERVER_END`   | `server-end/`  Right before the end of the site server block                   |
| `SERVER_POST`  | `server-post/` After site server block                                         |

#### Site Configuration

##### Site Mode & Per-Site Options

You can control per-site behaviour using `NGINX_SITE_<SITENAME>_` prefixed variables. The most important one is `MODE` which selects how the site is configured.

| Parameter              | Description                                                                                                             | Default  | Site | Advanced |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------- | -------- | ---- | -------- |
| `NGINX_MODE`           | Site mode: `normal`, `maintenance`, `proxy`, or `redirect`.                                                             | `normal` | x    |          |
|                        | If unset and `NGINX_SITE_<SITENAME>_ALLOW_DEFAULTS` is true, the global `NGINX_MODE` value is used; otherwise `normal`. |          |      |          |
| `NGINX_ALLOW_DEFAULTS` | When `true` (default) per-site settings inherit unspecified defaults                                                    | `TRUE`   |      |          |
|                        | from global variables (e.g. `NGINX_MODE`, `NGINX_WEBROOT`). Set to `false` to require explicit per-site settings.       |          |      |          |
| `NGINX_PROXY_URL`      | If `PROXY` set enter full url to proxy all traffic to eg `https://nfrastack.com:443`                                    |          | x    |          |
| `NGINX_REDIRECT_URL`   | If `REDIRECT` set enter full url to redirect (301) all traffic to eg `https://nfrastack.com`                            |          |      |          |

>> Mode options:
>>
>> `normal` renders webroot/index, authentication, client-cache, deny-hidden-files, logging tweaks, symlink handling, exploits/wellknown includes and other standard per-site fragments.
>> `maintenance` configures a maintenance page (local file, redirect or proxy depending on `NGINX_SITE_<SITENAME>_MAINTENANCE_*` vars).
>> `proxy` enables proxy-specific fragments including authentication helpers, denies/filters, and allows proxying to `NGINX_SITE_<SITENAME>_PROXY_URL`
>> `redirect` performs a 301 level redirection to the value `NGINX_SITE_<SITENAME>_REDIRECT_URL`
>>
>> Both `..PROXY_URL` and `..REDIRECT_URL` support `env:ENV_VAR_NAME` functionality where it will populate the URL with the value of a different environment variable.
>> Or even better use multiple+a string with `http://[env:ENV_VAR_NAME]:[env:ENV_VAR_NAME2]`

##### Additional Server & Site Variables

The following variables are commonly used to control TLS, HTTP listeners and other server/site level behaviours. Some are server-wide, others can be set on a per-site basis by prefixing with `NGINX_SITE_<SITENAME>_`.

| Parameter                          | Description                                                               | Default                     | Site | Advanced |
| ---------------------------------- | ------------------------------------------------------------------------- | --------------------------- | ---- | -------- |
| `NGINX_WEBROOT`                    | Where to serve content from inside the container                          | `/www/html`                 | x    |          |
| `NGINX_WEBROOT_SUFFIX`             | Append a suffix onto the nginx configuration to serve files               |                             | x    |          |
|                                    | from a subfolder e.g. `/public`                                           |                             |      |          |
| `NGINX_ENABLE_HTTP`                | Enable HTTP listener (site-level or global)                               | `TRUE`                      | x    |          |
| `NGINX_ENABLE_HTTPS`               | Enable HTTPS listener (site-level or global)                              | `FALSE`                     | x    |          |
| `NGINX_ENABLE_HTTP2`               | Enable HTTP/2 on TLS listeners                                            | `TRUE`                      | x    |          |
| `NGINX_ENABLE_HTTP3`               | Enable HTTP/3 (QUIC) on TLS listeners                                     | `TRUE`                      | x    |          |
| `NGINX_ENABLE_HTTP_TO_HTTPS`       | Redirect HTTP to HTTPS when both enabled                                  | `FALSE`                     | x    |          |
| `NGINX_HTTP_LISTEN_PORT`           | Port used for HTTP                                                        | `80`                        | x    |          |
| `NGINX_LISTEN_PORT`                | Nginx listening port                                                      | `${NGINX_HTTP_LISTEN_PORT}` | x    |          |
| `NGINX_HTTPS_LISTEN_PORT`          | Port used for HTTPS                                                       | `443`                       | x    |          |
| `NGINX_TLS_CERT_FILE`              | Path to TLS certificate file                                              | `/certs/nginx/cert.pem`     | x    |          |
| `NGINX_TLS_KEY_FILE`               | Path to TLS private key file                                              | `/certs/nginx/key.pem`      | x    |          |
| `NGINX_INDEX_FILE`                 | Default index files (space-separated list)                                | `index.html index.htm`      | x    |          |
| `NGINX_SERVER_NAME`                | Default server_name for sites                                             | `_`                         | x    |          |
| `NGINX_ENABLE_DENY_HIDDEN_FILES`   | Deny access to files beginning with `.`                                   | `FALSE`                     | x    |          |
| `NGINX_ENABLE_EXPLOIT_PROTECTION`  | Enable hardening of website                                               | `FALSE`                     | x    |          |
| `NGINX_ENABLE_WELLKNOWN_MIMETYPES` | Enable `.well-known` mimetype support                                     | `FALSE`                     | x    |          |
| `NGINX_ENABLE_LOG_FAVICON`         | Enable logging for favicon requests                                       | `TRUE`                      | x    |          |
| `NGINX_ENABLE_LOG_ROBOTS`          | Enable logging for robots.txt access                                      | `TRUE`                      | x    |          |
| `NGINX_ENABLE_SYMLINKS`            | Allow following symlinks in served content                                | `FALSE`                     | x    |          |
| `NGINX_ENABLE_CREATE_SAMPLE_HTML`  | If no `_INDEX_FILE` found - create a sample one to prove container works. | `TRUE`                      | x    |          |
| `NGINX_FORCE_RESET_PERMISSIONS`    | Force setting Nginx files ownership to web server user                    | `TRUE`                      | x    |          |

##### Authentication Options

You can choose to request visitors be authenticated before accessing your site.

| Parameter                                   | Description                                                                     | Default             | `_FILE` | Site | Advanced |
| ------------------------------------------- | ------------------------------------------------------------------------------- | ------------------- | ------- | ---- | -------- |
| `NGINX_AUTHENTICATION_TYPE`                 | Protect the site with `BASIC`, `LDAP`, `LLNG`                                   | `NONE`              |         | x    |          |
| `NGINX_AUTHENTICATION_TITLE`                | Challenge response when visiting protected site                                 | `Please login`      |         | x    |          |
| `NGINX_AUTHENTICATION_BASIC_USER1`          | If `BASIC` chosen enter this for the username to protect site                   | `admin`             | x       | x    |          |
| `NGINX_AUTHENTICATION_BASIC_PASS1`          | If `BASIC` chosen enter this for the password to protect site                   | `nfrastack`         | x       | x    |          |
| `NGINX_AUTHENTICATION_BASIC_USER2`          | As above, increment for more users                                              |                     | x       | x    |          |
| `NGINX_AUTHENTICATION_BASIC_PASS2`          | As above, increment for more users                                              |                     | x       | x    |          |
| `NGINX_AUTHENTICATION_LDAP_HOST`            | Hostname and port number of LDAP Server - eg  `ldap://ldapserver:389`           |                     | x       | x    |          |
| `NGINX_AUTHENTICATION_LDAP_BIND_DN`         | User to Bind to LDAP - eg   `cn=admin,dc=orgname,dc=org`                        |                     | x       | x    |          |
| `NGINX_AUTHENTICATION_LDAP_BIND_PW`         | Password for Above Bind User - eg   `password`                                  |                     | x       | x    |          |
| `NGINX_AUTHENTICATION_LDAP_BASE_DN`         | Base Distringuished Name - eg `dc=hostname,dc=com`                              |                     | x       | x    |          |
| `NGINX_AUTHENTICATION_LDAP_ATTRIBUTE`       | Unique Identifier Attrbiute -ie  `uid`                                          |                     |         | x    | x        |
| `NGINX_AUTHENTICATION_LDAP_SCOPE`           | LDAP Scope for searching - eg  `sub`                                            |                     |         | x    | x        |
| `NGINX_AUTHENTICATION_LDAP_FILTER`          | Define what object that is searched for (ie  `objectClass=person`)              |                     |         | x    | x        |
| `NGINX_AUTHENTICATION_LDAP_GROUP_ATTRIBUTE` | If searching inside of a group what is the Group Attribute - eg  `uniquemember` |                     |         | x    | x        |
| `NGINX_AUTHENTICATION_LLNG_HANDLER_HOST`    | If `LLNG` chosen use hostname and port of handler.                              |                     |         | x    |          |
|                                             | Add multiple by seperating with comments                                        | `llng-handler:2884` | x       | x    |          |
| `NGINX_AUTHENTICATION_LLNG_HANDLER_PORT`    | If `LLNG` chosen use this port for handler                                      | `2884`              | x       | x    |          |
| `NGINX_AUTHENTICATION_LLNG_BUFFERS`         | FastCGI Buffers for performance                                                 | `32 32k`            |         | x    | x        |
| `NGINX_AUTHENTICATION_LLNG_BUFFER_SIZE`     | FastCGI Buffer size for performance                                             | `32k`               |         | x    | x        |
| `NGINX_AUTHENTICATION_LLNG_ATTRIBUTE1`      | Syntax: HEADER_NAME, Variable, Upstream Variable - See note below               | See Example         |         | x    | x        |
| `NGINX_AUTHENTICATION_LLNG_ATTRIBUTE2`      | Syntax: HEADER_NAME, Variable, Upstream Variable - See note below               |                     |         | x    | x        |

>> When working with `NGINX_AUTHENTICATION_LLNG_ATTRIBUTE<NUM>` you will need to omit any `$` chracters from your string. It will be added in upon container startup.
>> Example  `NGINX_AUTHENTICATION_LLNG_ATTRIBUTE1=HTTP_AUTH_USER,uid,upstream_http_uid` will get converted into `HTTP_AUTH_USER,$uid,$upstream_http_uid` and get placed in the appropriate areas in the configuration.

#### Header Options

| Parameter              | Description                                   | Default                                             | _FILE | Advanced |
| ---------------------- | --------------------------------------------- | --------------------------------------------------- | ----- | -------- |
| `NGINX_ENABLE_HEADERS` | Enable custom header processing               | `TRUE`                                              |       |          |
| `NGINX_HEADER_FILE`    | Location of Header file to include            | `/etc/nginx/snippets/server.available/headers.conf` |       | x        |
| `NGINX_HEADERXX_NAME`  | Header Name eg 'Cross-Origin-Embedder-Policy' |                                                     | x     |          |
| `NGINX_HEADERXX_VALUE` | Header Value eg "require-corp"                |                                                     | x     |          |
| `NGINX_HEADERXX_FLAG`  | Header Name eg 'always'                       |                                                     | x     |          |

>> Replace `XX` with `01`-`99`
>> Be sure to include `/etc/nginx/snippets/server.available/headers.conf` server configuration block to use these.
>>
>> Setting a value of `null` or `none` to the `_NAME` will disable the header from being configured if set by an upstream image.

##### Custom Parameters

You can provide per-site FastCGI/UWSGI/SCGI (`<TYPE>`) parameter files or add individual params via environment variables.

>> When `NGINX_SITE_<SITENAME>_ENABLE_<TYPE>_PARAMS` is true the container will create the site folder and, if the target file does not already exist, copy the default template from `/container/data/nginx/params/<type>_params` into the resolved location.
>> Set `NGINX_SITE_<SITENAME>_<TYPE>FASTCGI_PARAMS_FILE` to an absolute path a path relative `sites.enabled/<sitename>`). If unset the default is `sites.enabled/<sitename>/<type>_params`.
>> You may append individual params using numbered variables `NGINX_SITE_<SITENAME>_<TYPE>01_PARAM`, `NGINX_SITE_<SITENAME>_<TYPE>02_PARAM`, ... where each value is `NAME,VALUE` and will be written as `<type>_param NAME VALUE;` into the site params file.
The token `{{<type>_params}}` can be used in site fragments and the container will replace it with the resolved params-file path.
>> `NGINX_SITE_<SITENAME>_ENABLE_<TYPE>_HTTPS` controls the `HTTPS` line inside the params file (`on`/`off`).
>>  Global `NGINX_FASTCGI## _PARAM` values are appended when `ALLOW_DEFAULTS` is enabled.

| Parameter                    | Description                                                   | Default         | Site | Advanced |
| ---------------------------- | ------------------------------------------------------------- | --------------- | ---- | -------- |
| `NGINX_ENABLE_<TYPE>_PARAMS` | Enable per-site TYPE params                                   | `FALSE`         | x    |          |
| `NGINX_<TYPE>_PARAMS_FILE`   | Absolute path or path relative to `sites.enabled/<sitename>/` | `<type>_params` | x    |          |
| `NGINX_<TYPE>01_PARAM`       | Numbered param entries (format: `NAME,VALUE`)                 |                 | x    |          |
| `NGINX_ENABLE_<TYPE>_HTTPS`  | Set HTTPS param value inside the params file (`on`/`off`)     | `FALSE`         | x    |          |


##### Include Options

You can inject include files into specific places of a generated site using environment variables. The container symlinks each listed path into the site fragment folder. Source files must exist and be readable inside the container at startup.

| Environment Variable                                     | Description                                                                      |
| -------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `NGINX_SITE_<SITENAME>_INCLUDE_CONFIGURATION_<FRAGMENT>` | Comma-separated absolute paths to include.                                       |
|                                                          | Set to `null` or `none` to explicitly disable any global fallback for that site. |

###### FRAGMENT Values

| `<FRAGMENT>`    | Destination folder (inside `${CONFIG_PATH%/}/sites.enabled/<sitename>/`) |
| --------------- | ------------------------------------------------------------------------ |
| `LOCATION`      | `location/` main Location Blocks                                         |
| `LOCATION_PRE`  | `location-pre/` Before main Location Blocks                              |
| `LOCATION_POST` | `location-post/` After main Location Blocks                              |
| `SERVER_PRE`    | `server-pre/` Before site server block                                   |
| `SERVER_BEGIN`  | `server-begin/` Start of the site server block                           |
| `SERVER_END`    | `server-end/`  Right before the end of the site server block             |
| `SERVER_POST`   | `server-post/` After site server block                                   |

##### Logging Options

| Parameter                  | Description                               | Default       | Site | Advanced |
| -------------------------- | ----------------------------------------- | ------------- | ---- | -------- |
| `NGINX_LOG_ACCESS_PATH`    | Location inside container for saving logs | `/logs/nginx` | x    |          |
| `NGINX_LOG_ACCESS_FILE`    | Nginx websites access logs                | `access.log`  | x    |          |
| `NGINX_LOG_ACCESS_FORMAT`  | Log Format `standard` or `json`           | `standard`    | x    |          |
| `NGINX_LOG_BLOCKED_PATH`   | Location inside container for saving logs | `/logs/nginx` | x    |          |
| `NGINX_LOG_BLOCKED_FILE`   | If exploit protection `TRUE`              | `blocked.log` | x    |          |
| `NGINX_LOG_BLOCKED_FORMAT` | Log Format `standard` or `json`           | `standard`    | x    |          |
| `NGINX_LOG_ERROR_PATH`     | Location inside container for saving logs | `/logs/nginx` | x    |          |
| `NGINX_LOG_ERROR_FILE`     | Nginx server and websites error log name  | `error.log`   | x    |          |
| `NGINX_LOG_LEVEL_ERROR`    | How much verbosity to use with error logs | `warn`        | x    |          |

##### Client Cache Configuration

| Parameter                             | Description                                                          | Default                              | Site | Advanced |
| ------------------------------------- | -------------------------------------------------------------------- | ------------------------------------ | ---- | -------- |
| `NGINX_ENABLE_CLIENT_CACHE`           | Enabling Client caching                                              | `FALSE`                              | x    |          |
| `NGINX_CLIENT_CACHE`                  | Types of client cache to enable (AUDIO,CSS,HTML,IMAGE,JS,MISC,VIDEO) | `AUDIO,CSS,HTML,IMAGE,JS,MISC,VIDEO` | x    | x        |
| `NGINX_CLIENT_CACHE_AUDIO_EXPIRES`    | Audio cache expiration                                               | `15d`                                | x    | x        |
| `NGINX_CLIENT_CACHE_AUDIO_EXTENSIONS` | Audio file extensions to cache                                       | `mp3 ogg wav`                        | x    | x        |
| `NGINX_CLIENT_CACHE_AUDIO_LOG`        | Enable logging for audio cache                                       | `TRUE`                               | x    | x        |
| `NGINX_CLIENT_CACHE_CSS_EXPIRES`      | CSS cache expiration                                                 | `30d`                                | x    | x        |

##### Maintenance Options

| Parameter                        | Description                                                  | Default                             | Site | Advanced |
| -------------------------------- | ------------------------------------------------------------ | ----------------------------------- | ---- | -------- |
| `NGINX_MAINTENANCE_TYPE`         | Serve `local` file, or `redirect` or `proxy` to a URL        | `local`                             | x    |          |
| `NGINX_MAINTENANCE_PATH`         | (local) Path where the maintenance page resides              | `/container/data/nginx/maintenance` | x    |          |
| `NGINX_MAINTENANCE_FILE`         | (local) File to load while in maintenance mode               | `index.html`                        | x    |          |
| `NGINX_MAINTENANCE_REMOTE_URL`   | (local) If you wish to download an html file from a          |                                     | x    |          |
|                                  | remote location to overwrite the above enter the URL here    |                                     | x    |          |
| `NGINX_MAINTENANCE_PROXY_URL`    | What url eg `https://example.com` to transparently proxy for |                                     | x    |          |
|                                  | the user when they visit the site                            | `http://maintenance`                | x    |          |
| `NGINX_MAINTENANCE_REDIRECT_URL` | What url eg `https://example.com` to redirect                |                                     | x    |          |
|                                  | in a uers browser when they visit the site                   |                                     | x    |          |

You can also enter into the container and type `maintenance ARG`, where ARG is either `ON`,`OFF`, or `SLEEP (seconds)` which will temporarily place the site in maintenance mode and then restore it back to normal after time has passed.

##### MTLS Options (WIP)

| Parameter                    | Description                                                          | Default | Site | Advanced |
| ---------------------------- | -------------------------------------------------------------------- | ------- | ---- | -------- |
| `NGINX_TLS_CLIENT_CERT_FILE` | (mtLS) Client Certificate file eg `/certs/nginx/ca-certificates.crt` |         | x    | x        |
| `NGINX_TLS_VERIFY_CLIENT`    | (mTLS) Verify client certificates                                    | `FALSE` | x    | x        |
| `NGINX_TLS_VERIFY_DEPTH`     | (mTLS) Verification depth for client certificate chain               | `2`     | x    | x        |

## Users and Groups

| Type  | Name       | ID  |
| ----- | ---------- | --- |
| User  | `nginx`    | 80  |
| Group | `www-data` | 82  |

### Networking

| Port | Protocol | Description |
| ---- | -------- | ----------- |
| `80` | tcp      | Nginx       |

* * *

## Maintenance

### Shell Access

For debugging and maintenance, `bash` and `sh` are available in the container.

## Support & Maintenance

- For community help, tips, and community discussions, visit the [Discussions board](/discussions).
- For personalized support or a support agreement, see [Nfrastack Support](https://nfrastack.com/).
- To report bugs, submit a [Bug Report](issues/new). Usage questions will be closed as not-a-bug.
- Feature requests are welcome, but not guaranteed. For prioritized development, consider a support agreement.
- Updates are best-effort, with priority given to active production use and support agreements.

## References

* https://nginx.org/

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

