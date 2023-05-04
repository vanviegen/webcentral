# Webcentral

Host multiple sandboxed started-on-demand web applications on a single machine. Create a DNS (sub)domain for your application, put it in a directory with the domain as its name, and it's good to go! This is especially convenient when used with a wildcard DNS record, for quickly throwing things online.

## Features

- Based on directory names that should match the domain of an incoming request, Webcentral will:
	- Start a Node.js application on-demand, within a Firejail sandbox.
	- Run a web service within a trivially easy to configure Docker environment on-demand.
	- Host static files.
	- Proxy requests to some (remote) service, optionally masquerading the original domain.
	- Browser redirect requests.
- Restart applications without downtime when files are changed, for easy updates.
- Shut down applications after some period of inactivity.
- Automatically set up HTTPS using LetsEncrypt, and redirects HTTP requests to HTTPS.
- Automatically redirect `example.com` to `www.example.com`, or the other way around.
- Passthrough WebSocket traffic.
- Run projects on behalf of multiple users, when started as root. Applications run with the user's permissions. The first user to claim a domain will get to keep it.
- Write application stdout and stderr to rotating log files in the project directory.
- Rewrite request paths using regular expressions.

**Caveats:**
- This is a single process Node.js application. Though it should be relatively fast, don't expect miracles. Scaling up Webcentral should not be that difficult though.
- Although Firejail and Docker will add a layer of security compared to running random code without a sandbox, the way we're using these from Webcentral has not been scrutinized all that well. Also, Webcentral itself may add additional attack surface. In other words: don't rely on this too much for security.

## Installation

Installation should be something along the lines of:

```sh
sudo apt install nodejs npm git firejail docker.io
git clone https://github.com/vanviegen/webcentral.git
cd webcentral
npm install
```

## Usage

`node index.js --email you@example.com`

This will start the Webcentral server, dispatching to node projects in the `webcentral-projects` directory in your home directory. If the above command was run as root, the `public-node-project` directories of all users will be searched, and projects will be run as their owning users.

The `webcentral-projects` directories should contain subdirectories that have the name of the (sub)domains they are claiming. For instance: `/home/frank/webcentral-projects/example.com/`. Based on the contents, a project can be treated in various ways:

### Project types

1. **Application.** If `webcentral.ini` exists and has a top-level `command` property or `[docker]` section, a server process will will be run from within a Firejail sandbox or Docker container. The command is expected to set up an HTTP service on port $PORT (which will be 8000 by default when Docker is used). This shouldn't take too long, as the incoming HTTP request will be stalled until the server is ready.
    - Firejail is the default option. It allows read-only access to system directories of the host system, such as `/bin` and `/usr`, but doesn't expose files like those in your home directory.
    - Docker is selected by creating a `[docker]` section in the .ini-file. No files of the host system, except from the project directory itself, will be exposed. Instead, a separate Linux distribution is created for the application. Generally, this will consume more memory and take a bit longer to start than when using Firejail. By default the container will run a pristine Alpine linux image, but options in the `[docker]` section of the .ini-file can be used to change that:
      - `base` sets the Docker base image to start with.
      - `commands` is an array of commands used to build the Docker image. Each command can either be a string, which will be executed as a shell command, or an array of strings, which will be executed without involving a shell.
      - `packages` is an array of packages to install on the base system. This only works on base systems that offer either `apt-get` (Debian/Ubuntu) or `apk` (Alpine) as a means to install them. This is just a shortcut for prepending `commands`.
      - `mounts` is an array of directories in the context of the Docker container that should be persisted. The directories can be absolute or relative to the Docker workdir (`/app`). In the host system, empty directories that don't exist yet are automatically created in the `_webcentral_data/mounts/` directory. The `/app` directory itself is always mounted, unless `mount_app_dir` is set to `false`.
      - `http_port` is the TCP port within the container that the HTTP server will be running on. It defaults to 8000.
      - `app_dir` is the directory with the Docker container to which the host's project directory will be mounted. It defaults to `/app`.
      - `mount_app_dir` can be set to `false` in order to prevent the host's project directory from being mounted.
    
    Example `webcentral.ini` using PHP from the host system:
    ```ini
    command = php -S 0.0.0.0:$PORT -file test.php
    ```
    
    And using PHP from a Docker image:
    ```ini
    command = php -S 0.0.0.0:$PORT -file test.php
    [docker]
    base = debian
    packages[] = php
    packages[] = composer
    commands[] = composer install
    ```
    
    Or to just run the default command of a Docker image:
    ```ini
    [docker]
    base = some-docker-image:version
    ```
    
    A real-world example for setting up a Trilium Notes server:
    ```ini
    command = node /usr/src/app/src/www
    [docker]
    base = zadam/trilium:0.47.6
    http_port = 8080
    ```
  - **Forward.** Otherwise, when the .ini-file has a top-level `port` or `socket_path` property, requests will be forwarded to this port or UNIX domain socket, without modifying the `Host:` header. When used with `port`, the `host` property can specify a host name or ip address to use -- it defaults to localhost.
    ```ini
    port = 3000
    host = 192.168.10.20
    ```
    Or
    ```ini
    socket_path = /my/path/test.socket
    ```
3. **Redirect.** If `webcentral.ini` exists and has a top-level `redirect` property, all requests will receive an HTTP 301 redirect to the URL given in that property, concatenated with the path and query string of the request.
    ```ini
    redirect = https://new-service-name.example.com
    ```
4. **Proxy.** (Experimental!) If `webcentral.ini` exists and has a top-level `proxy` property containing a URL, requests will be proxied to that URL. This is similar to forwarding, except that proxying is not visible to the target host as headers such as `Host:` are rewritten.
    ```ini
    proxy = https://www.google.com
    ```
5. **Node.js application.** If `package.json` exists in the project directory, the project is assumed to be an *Application* and the command is set to `['npm', 'start']`. This allows hosting Node.js projects without even having a `webcentral.ini` file.
   - `npm start` within the project directory should bring up an HTTP server on port `process.env.PORT`. This shouldn't take too long, as the HTTP client will be kept waiting.
6. **Static server.** In other cases, everything under `public/` in the project directory will be **served statically** as just a bunch of files.

### Reloading
Applications will be automatically shut down when...
1. The service has been inactive for 5 minutes. This period can be overridden or disabled using the `timeout` property in the `[reload]` section of the `webcentral.ini`. It indicates the time in seconds. Zero disables inactivity shutdown.
2. When any of the files in the application directory change. By default, the following file patterns are excluded from this:
   - `_webcentral_data` (A file or directory with this name in the root of the project directory.)
   - `data`
   - `log`
   - `logs`
   - `home`
   - `node_modules`
   - `**/*.log` (A file or directory with a name ending in *.log* in the root directory or any subdirectory.)
   - `**/.*` (Hidden files.)
   This behaviour can be overriden using the `include` and `exclude` properties in the `[reload]` section of `webcentral.ini`. Both can be string arrays containing patterns like the above. Exclusion always overrules inclusion. When `include` is not set, everything will be included by default. Even when `include` is manually set, `webcentral.ini` will always be added to it automatically, to make sure errors can be corrected. Similarly, `exclude` will always have `_webcentral_data` appended to it, because it makes little sense to reload for log messages written by Webcentral or data modified by the app.
   ```ini
   command = ./start.sh --production
   [reload]
   timeout = 0 ; Disable inactivity shutdown
   include[] = src ; Reload for changes in src/ directory
   include[] = config.yaml ; And for changes to this file
   exclude[] = src/build ; But ignore the build directory
   exclude[] = **/*.bak ; And ignore any .bak file
   ```
   
### Rewrites (Experimental!)
Request paths can be rewritten before they are handled. To do that, create a `[rewrite]` section in the `webcentral.ini` of a project. Its keys and values will be applied in order as regular expressions and their replacement values. A regular expression must match the entire path string. The replacement string can use `$1`, `$2` etc to captured expressions. After a match, any further replacement rules are skipped. 

In case a replacement results in a path that matches `webcentral://<NAME>/<PATH>`, the request will be handed of to a Webcentral project named `<NAME>`, giving it `/<PATH>` as its request path. The `<NAME>` of that Webcentral project does not need to resolve to this host in DNS.

```ini
[rewrite]
/api/(.*) = webcentral://my-api/$1 ; let these requests be handled by a Webcentral service named my-api
/blog/(.*?)/.* = /articles/$1.html ; ignore the verbose title in the URL and add .html to find the static article file
/favicon.ico = /facicon.ico ; make sure the following rule does not apply for favicons
/[^/]* = /index.html ; any other top-level paths are redirect to index.html
```

### Environment variables
All properties in the `[environment]` section are set as environment variables for the web server command that will be executed. For example:
```ini
[docker]
base = bitwardenrs/server:alpine
mounts[] = data
mounts[] = web-vault
[environment]
ROCKET_PORT = 8000
WEB_VAULT_ENABLED = true
```

### Redirect http/https
Requests can be redirected from http to https, or the other way around. This can be configured through the `redirect_http` and `redirect_https` boolean properties. The former has a default value that can be set using `--redirect-http` command line argument. The latter defaults to `false`.

This example redirects https traffic to http:
```ini
redirect_http = false
redirect_https = true
```

## Options

| Option | Description |
| --- | --- |
| `--email=EMAIL` | Set the email address used for LetsEncrypt to `EMAIL`. Defaults to the $EMAIL environment variable. An email address is required, unless `--https=0`. |
| `--projects=DIR` | Search for projects in DIR, where `DIR` can be a `glob` expression. Projects need to be directories (containing a `package.json` file), named exactly like the domain the are serving. Defaults to `/home/*/webcentral-projects` when run as root, or to `$HOME/webcentral-projects` otherwise. |
| `--config=DIR` | Directory where domain to directory mappings and LetsEncrypt config are stored. Defaults to `/var/lib/webcentral` when run as root, or to `$HOME/.webcentral` otherwise.
| `--https=PORT` | Run the HTTPS server on TCP port `PORT`. Defaults to 443. Set to 0 to disable HTTPS. |
| `--http=PORT` | Run the HTTP server on TCP port `PORT`. Defaults to 80. Set to 0 to disable HTTP. |
| `--redirect-http=BOOL` | When `true` (as it is by default) and both `http` and `https` are not 0, incoming HTTP requests will be redirected to HTTPS. When set to `false`, requests are handled on both HTTP and HTTPS. This behaviour can be overriden by individual projects. |
| `--redirect-www=BOOL` | When `true` (as it is by default), "www.example.com" will be redirect to "example.com" if the former doesn't exist but the latter does, and vice versa. |
| `--firejail=BOOL` | Set to `false` to disable the use of Firejail containing Node processes. This is bad for security and may cause process leaks. Defaults to `true`. |
| `--acme-url=URL` | Use the given ACME directory URL. Defaults to using Let's Encrypt: `https://acme-v02.api.letsencrypt.org/directory`. BuyPass is also known to work: `https://api.buypass.com/acme/directory`. |
| `--acme-version=VER` | Try to use the given ACME protocol version. Defaults to `draft-11`. |

## Log files

Output of (and about) client projects is written to `_webcentral_data/log/<DATE>.log` in the project directory. Log files are automatically deleted after three weeks. This is currently not configurable (except by trivially modifying the source code).

Projects can enable request logging by setting the following property in `webcentral.ini`:

```ini
log_requests = true
```


## Starting from systemd

Create a file named `/etc/systemd/system/webcentral.service` containing:

```ini
[Service]
ExecStart=/usr/bin/nodejs /PATH/TO/webcentral/index.js --email YOUR-EMAIL-ADDRESS
Restart=always

[Install]
WantedBy=multi-user.target
```

To start the service:

```sh
sudo systemctl daemon-reload
sudo systemctl start webcentral
```

To have the service starts after reboots:

```sh
sudo systemctl enable webcentral
```

Make sure no other servers are already running on port 80 or 443. To see any non-project-specific problems:

```sh
sudo systemctl status webcentral -n 20
```

