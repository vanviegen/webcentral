# node-central

## Features

node-central delegates requests to other Node applications, based on the request subdomain.

- Starts apps on-demand (< 1s) and stops them after 5m of inactivity.
- Restarts apps when files are changed, without downtime.
- Runs apps in a restricted environment (firejail), adding some security.
- Automatically sets up HTTPS using LetsEncrypt.
- Supports WebSocket.
- Can run projects on behalf of multiple users, when started as root. The first user to claim a domain will get to keep it.
- Writes project console output to rotating log files in the project directory.
- Zero configuration.

## Installation

Required software, should be available in your PATH:

- node
- firejail (`apt install firejail`)

## Usage

`node index.js`

Will start the node-central server, dispatching to node projects in de `public-node-projects` directory in your home directory. If the above command was run as root, the `public-node-project` directory of all users will be searched, and the project will be run as the owning user.

The above does require the $EMAIL environment variable to be set, for use with LetsEncrypt.

## Options

| Option | Description |
| --- | --- |
| --email EMAIL | Set the email address used for LetsEncrypt to EMAIL. Defaults to the $EMAIL environment variable. |
| --projects DIR | Search for projects in DIR, where DIR can be a `glob` expression. Projects need to be directories (containing a `package.json` file), named exactly like the domain the are serving. Defaults to `/home/*/public-node-projects` when run as root, or to `$HOME/public-node-projects` otherwise. |
| --config DIR | Directory where domain to directory mappings and LetsEncrypt config are stored. Defaults to `/var/lib/node-central` when run as root, or to `$HOME/.node-central` otherwise.

