# node-central

Node-central makes it easy to run (many) Node.js applications (and other web projects) on a single server.

## Features

- Starts Node.s applications on-demand (~ 1s) and stops them after 5m of inactivity.
- Restarts applications when any files are changed, without downtime.
- Runs applications in a restricted environment (firejail), adding some security.
- Automatically sets up HTTPS using LetsEncrypt, and redirects HTTP traffic to HTTPS.
- Supports WebSocket passthrough.
- Can run projects on behalf of multiple users, when started as root. Runs project as the user. The first user to claim a domain will get to keep it.
- Writes project console output to rotating log files in the project directory.
- Trivially easy static file serving, as well as proxying, forwarding or redirecting to other web sites.

This is mostly useful to get (many) small web applications or experiments up-and-running quickly, safe-ish and on their own (wildcard) subdomains.


## Installation

Installation should be something along the lines of:

```sh
sudo apt install nodejs npm git firejail
git clone https://github.com/vanviegen/node-central.git
cd node-central
npm install
```

## Usage

`node index.js --email you@example.com`

This will start the node-central server, dispatching to node projects in the `public-node-projects` directory in your home directory. If the above command was run as root, the `public-node-project` directories of all users will be searched, and projects will be run as their owning users.

The `public-node-projects` directories should contain subdirectories that have the name of the (sub)domains they are claiming. For instance: `/home/frank/public-node-projects/example.com/`. Based on the contents, a project can be treated in various ways:

1. If the project has a `/package.json` file, it will be run as a Node.js project.
  - `npm start` within the project directory should bring up an HTTP server on port `process.env.PORT`. This shouldn't take too long, as the HTTP client will be kept waiting.
  - If WebSocket is used, it should be made available over the same port.
  - Only limited access to the host system is provided. (See the node-central source code and firejail documentation for details -- sorry.)
2. If the project has a `/node-central.json` file, requests will be delegated to a service listen in that file.
forward, proxy or redirect, indicated by the presence of a `node-central.json` file. The file should consist of a valid JSON object that can have either of the following keys:
  - `port` (and optionally `host`): Requests will be forwarded to another web service, without modifying the `Host:` header. Example: `{"port": 8080, "host": "localhost"}`
  - `proxy`: Requests will be proxied to another web service, modifying `Host:` such that the target doesn't notice it is being proxied. Example: `{"proxy": "https://www.google.com"}`
  - `redirect`: Requests will return a 301 redirect to another web service. Example: `{"proxy": "https://new-app-name.example.com"}`
3. In other cases, the project directory will be served statically as just a bunch of files.


## Options

| Option | Description |
| --- | --- |
| `--email=EMAIL` | Set the email address used for LetsEncrypt to `EMAIL`. Defaults to the $EMAIL environment variable. |
| `--projects=DIR` | Search for projects in DIR, where `DIR` can be a `glob` expression. Projects need to be directories (containing a `package.json` file), named exactly like the domain the are serving. Defaults to `/home/*/public-node-projects` when run as root, or to `$HOME/public-node-projects` otherwise. |
| `--config=DIR` | Directory where domain to directory mappings and LetsEncrypt config are stored. Defaults to `/var/lib/node-central` when run as root, or to `$HOME/.node-central` otherwise.
| `--https=PORT` | Run the HTTPS server on TCP port `PORT`. Defaults to 443. Set to 0 to disable HTTPS. |
| `--http=PORT` | Run the HTTP server on TCP port `PORT`. Defaults to 80. Set to 0 to disable HTTP. |
| `--redirect-http=BOOL` | When `true` (as it is by default) and both `http` and `https` are not 0, incoming HTTP requests will be redirected to HTTPS. When set to `false`, requests are handled on both HTTP and HTTPS. |
| `--optional-www=BOOL` | When `true` (as it is by default), "www.example.com" will be looked up as "example.com" if it doesn't exist, and vice versa. |
| `--firejail=BOOL` | Set to `false` to disable the use of Firejail containing Node processes. This is bad for security and may cause process leaks. Defaults to `true`. |


## Log files

Output of (and about) client projects is written to `log/node-central.log` in the project directory. Log files are rotated and compressed daily, and deleted after two weeks. This is currently not configurable (except by trivially modifying the source code).


## Starting from systemd

Create a file named `/etc/systemd/system/node-central.service` containing:

```ini
[Service]
ExecStart=/usr/bin/nodejs /PATH/TO/node-central/index.js --email YOUR-EMAIL-ADDRESS
Restart=always

[Install]
WantedBy=multi-user.target
```

To start the service:

```sh
sudo systemctl daemon-reload
sudo systemctl start node-central
```

To have the service starts after reboots:

```sh
sudo systemctl enable node-central
```

Make sure no other servers are already running on port 80 or 443. To see any non-project-specific problems:

```sh
sudo systemctl status node-central -n 20
```

