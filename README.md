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
- Passthrough WebSocket traffic.
- Run projects on behalf of multiple users, when started as root. Applications run with the user's permissions. The first user to claim a domain will get to keep it.
- Write application stdout and stderr to rotating log files in the project directory.

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

1. If the project has a `/package.json` file, it will be run as a **Node.js project**.
  - `npm start` within the project directory should bring up an HTTP server on port `process.env.PORT`. This shouldn't take too long, as the HTTP client will be kept waiting.
  - If WebSocket is used, it should be made available over the same port.
  - Only limited access to the host system is provided. (See the Webcentral source code and Firejail documentation for details -- sorry.) The jail can be disabled using the `--firejail=false` flag. Or, for more flexibility, Docker can be used to setup the Node.js environment. Please ready on...
2. Otherwise, if the project has a `/webcentral.ini` file, requests will be delegated to a service listen in that file.
  - **Application.** When the .ini-file has a top-level `command` property, this command will be run from within a Firejail or Docker sandbox. The command is expected to set up an HTTP service on port 8000.
    - Firejail is the default option. It allows read-only access to system directories of the host system, such as `/bin` and `/usr`, but doesn't expose files like those in your home directory.
    - Docker is selected by creating a `[docker]` section in the .ini-file. No files of the host system will be exposed. Instead, a separate Linux distribution is created for the application. Generally, this will consume more memory and take a bit longer to start than when using Firejail. By default the container will run a pristine Alpine linux image, but options in the `[docker]` section of the .ini-file can be used to change that:
      - `base` sets the Docker base image to start with.
      - `commands` is an array of commands used to build the Docker image. Each command can either be a string, which will be executed as a shell command, or an array of strings, which will be executed without involving a shell.
      - `packages` is an array of packages to install on the base system. This only works on base systems that offer either `apt-get` (Debian/Ubuntu) or `apk` (Alpine) as a means to install them. This is just a shortcut for prepending `commands`.
    
    Example `webcentral.ini` using PHP from the host system:
    ```ini
    command = php -S 0.0.0.0:$PORT -file test.php
    ```
    And using PHP from a Docker image:
    ```ini
    command = php -S 0.0.0.0:$PORT -file entrypoint.php
    [docker]
    base = debian
    packages[] = php
    packages[] = composer
    commands[] = composer install
    ```
  - **Forward.** Otherwise, when the .ini-file has a top-level `port` property, requests will be forwarded to this port, without modifying the `Host:` header. The `host` property can specify a host name or ip address to use -- it defaults to localhost.
    ```ini
    port = 3000
    host = 192.168.10.20
    ```
  - **Proxy.** (Experimental) Otherwise, when `webcentral.ini` has a top-level `proxy` property containing a URL, requests will be proxied to that URL. This is similar to forwarding, except that proxying is not visible to the target host as headers such as `Host:` are rewritten.
    ```ini
    proxy = https://www.google.com
    ```
  - **Redirect.** Otherwise, when a `redirect` property is present, all requests will receive an HTTP 301 redirect to the URL given in that property, concatenated with the path and query string of the request.
    ```ini
    redirect = https://new-service-name.example.com
    ```
3. In other cases, everything under `public/` in the project directory will be **served statically** as just a bunch of files.

### Reloading
Node.js and Docker applications will be automatically shut down when...
1. The service has been inactive for 5 minutes. This period can be overridden or disabled using the `timeout` property in the `[reload]` section of the `webcentral.ini`. It indicates the time in seconds. Zero disables inactivity shutdown.
2. When any of the files in the application directory change. By default, the following file patterns are excluded from this:
   - `data` (A file or directory with this name in the root of the project directory.)
   - `log`
   - `logs`
   - `node_modules`
   - `**/*.log` (A file or directory with a name ending in *.log* in the root directory or any subdirectory.)
   - `**/.*` (Hidden files.)
   This behaviour can be overriden using the `include` and `exclude` properties in the `[reload]` section of `webcentral.ini`. Both can be string arrays containing patterns like the above. Exclusion always overrules inclusion. When `include` is not set, everything will be included by default. Even when `include` is manually set, `webcentral.ini` will always be added to it automatically, to make sure errors can be corrected. Similarly, `exclude` will always have `log` appended to it, because it makes little sense to reload for each log message written by Webcentral.
   ```ini
   command = ./start.sh --production
   [reload]
   timeout = 0 ; Disable inactivity shutdown
   include[] = src ; Reload for changes in src/ directory
   include[] = config.yaml ; And for changes to this file
   exclude[] = src/build ; But ignore the build directory
   exclude[] = **/*.bak ; And ignore any .bak file
   ```

## Options

| Option | Description |
| --- | --- |
| `--email=EMAIL` | Set the email address used for LetsEncrypt to `EMAIL`. Defaults to the $EMAIL environment variable. An email address is required, unless `--https=0`. |
| `--projects=DIR` | Search for projects in DIR, where `DIR` can be a `glob` expression. Projects need to be directories (containing a `package.json` file), named exactly like the domain the are serving. Defaults to `/home/*/webcentral-projects` when run as root, or to `$HOME/webcentral-projects` otherwise. |
| `--config=DIR` | Directory where domain to directory mappings and LetsEncrypt config are stored. Defaults to `/var/lib/webcentral` when run as root, or to `$HOME/.webcentral` otherwise.
| `--https=PORT` | Run the HTTPS server on TCP port `PORT`. Defaults to 443. Set to 0 to disable HTTPS. |
| `--http=PORT` | Run the HTTP server on TCP port `PORT`. Defaults to 80. Set to 0 to disable HTTP. |
| `--redirect-http=BOOL` | When `true` (as it is by default) and both `http` and `https` are not 0, incoming HTTP requests will be redirected to HTTPS. When set to `false`, requests are handled on both HTTP and HTTPS. |
| `--optional-www=BOOL` | When `true` (as it is by default), "www.example.com" will be looked up as "example.com" if it doesn't exist, and vice versa. |
| `--firejail=BOOL` | Set to `false` to disable the use of Firejail containing Node processes. This is bad for security and may cause process leaks. Defaults to `true`. |


## Log files

Output of (and about) client projects is written to `log/webcentral_<DATE>.log` in the project directory. Log files are automatically deleted after three weeks. This is currently not configurable (except by trivially modifying the source code).


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

