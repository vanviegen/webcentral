# node-central

Node-central delegates web requests to other Node applications, based on the request's domain.

## Features

- Starts apps on-demand (~ 1s) and stops them after 5m of inactivity.
- Restarts apps when files are changed, without downtime.
- Runs apps in a restricted environment (firejail), adding some security.
- Automatically sets up HTTPS using LetsEncrypt.
- Redirects HTTP traffic to HTTPS.
- Supports WebSocket passthrough.
- Can run projects on behalf of multiple users, when started as root. Runs project as the user. The first user to claim a domain will get to keep it.
- Writes project console output to rotating log files in the project directory.
- Zero configuration.

This is mostly useful to get (many) small web apps or experiments up-and-running quickly, safe-ish and on their own (sub)domains.


## Installation

Installation should be something along the lines of:

```sh
sudo apt install nodejs npm git firejail
git clone https://github.com/vanviegen/node-central.git
cd node-central
npm install
```

## Usage

`node index.js`

This will start the node-central server, dispatching to node projects in the `public-node-projects` directory in your home directory. If the above command was run as root, the `public-node-project` directories of all users will be searched, and projects will be run as their owning users.

The above does require the $EMAIL environment variable to be set, for use with LetsEncrypt. (See: Options.)


## Expectations of client projects

- `npm start` within the project directory should bring up an HTTP server on port `process.env.PORT`. This shouldn't take too long, as the HTTP client will be kept waiting.
- If WebSocket is used, it should be made available over the same port.
- Only limited access to the host system is provided. (See the node-central source code and firejail documentation for details -- sorry.)


## Options

| Option | Description |
| --- | --- |
| `--email=EMAIL` | Set the email address used for LetsEncrypt to `EMAIL`. Defaults to the $EMAIL environment variable. |
| `--projects=DIR` | Search for projects in DIR, where `DIR` can be a `glob` expression. Projects need to be directories (containing a `package.json` file), named exactly like the domain the are serving. Defaults to `/home/*/public-node-projects` when run as root, or to `$HOME/public-node-projects` otherwise. |
| `--config=DIR` | Directory where domain to directory mappings and LetsEncrypt config are stored. Defaults to `/var/lib/node-central` when run as root, or to `$HOME/.node-central` otherwise.
| `--https=PORT` | Run the HTTPS server on TCP port `PORT`. Defaults to 443. Set to 0 to disable HTTPS. |
| `--http=PORT` | Run the HTTP server on TCP port `PORT`. Defaults to 80. Set to 0 to disable HTTP. |
| `--redirect-http=BOOL` | When `true` (as it is by default) and both `http` and `https` are not 0, incoming HTTP requests will be redirected to HTTPS. When set to `false`, requests are handled on both HTTP and HTTPS. |
| `--firejail=BOOL` | Set to `false` to disable the use of Firejail containing Node processes. This is bad for security and may cause process leaks. Defaults to `true`. |


## Log files

Output of (and about) client projects is written to `log/node-central.log` in the project directory. Log files are rotated and compressed daily, and deleted after two weeks. This is currently not configurable (except by trivially modifying the source code).


## Starting from systemd

Create a file named `/etc/systemd/system/node-central.service` containing:

```ini
[Service]
ExecStart=/usr/bin/nodejs /path/to/node-central/index.js --email your-email-address
Restart=always

[Install]
WantedBy=multi-user.target
```

You do of course need to modify the node-central path and email address.

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

