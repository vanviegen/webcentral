'use strict';

const childProcess = require('child_process');
const fs = require('fs');
const joinPath = require('path').join;
const getPort = require('get-port');
const httpProxy = require('http-proxy');
const net = require('net');
const serveStatic = require('serve-static');
const ini = require('ini');
const parseUrl = require('url').parse;

const index = require('./index');
const Logger = require('./logger');


/* Hot-patch for http-proxy https://github.com/http-party/node-http-proxy/pull/1379 */
(function() {
	let wsi = require('http-proxy/lib/http-proxy/passes/ws-incoming')
	let old = wsi.XHeaders;
	wsi.XHeaders = function(req, socket, options) {
		old.call(this, req, socket, options);
		req.headers['x-forwarded-host'] = req.headers['x-forwarded-host'] || req.headers['host'] || '';
		if (req.headers['x-forwarded-proto']) {
			// flask_socketio can't handle proto wss. not sure if it should, but we'll work around it here:
			req.headers['x-forwarded-proto'] = req.headers['x-forwarded-proto'].replace(/ws/g, 'http');
		}
	};
})();


function portReachable(port) {
	return new Promise(function(resolve) {
		const socket = new net.Socket();

		function onError(){
			socket.destroy();
			resolve(false);
		}

		socket.setTimeout(1000);
		socket.on('error', onError);
		socket.on('timeout', onError);

		socket.connect(port, 'localhost', function(){
			socket.write("HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n");
			socket.on('data', function(data) {
				// any response is good enough for us!
				socket.end();
				resolve(true);
			});
		});
	});
}

function wildcardsToRegExp(wildcards) {
	if (!wildcards) return;
	return new RegExp('^(' + wildcards.map(function(wildcard) {
		return wildcard.replace(/\*\*\/|[-[\]{}()+*?.,\\^$|#\s]/g, function(match) {
			if (match==='**/') return '(.*/)?';
			if (match==='*') return '[^/]*';
			if (match==='?') return '[^/]';
			return '\\'+match;
		});
	}).join('|') + ')$');
}


function makePathSync(path, uid) {
	if (uid) {
		let oldEuid = process.geteuid();
		try {
			process.seteuid(uid);
			fs.mkdirSync(path, {recursive: true});
		} finally {
			process.seteuid(oldEuid);
		}
	}
	else {
		fs.mkdirSync(path, {recursive: true});
	}
}



const all = {};

module.exports = class Project {

	static get(dir) {
		return all[dir] = all[dir] || new Project(dir);
	}

	static stopAll() {
		for(let dir in all) {
			all[dir].stop();
		}
	}
	
	constructor(dir) {
		this.dir = dir;
		let parts = dir.split('/');
		this.domain = parts[parts.length-1] || parts[parts.length-2];
		this.queue = [];
		this.lastUse = new Date().getTime();
		this.watchers = [];

		if (process.getuid()==0) { // running as root -- process should run as owner of project directory
			let stat = fs.statSync(this.dir);
			this.uid = stat.uid;
			this.gid = stat.gid;
		}

		let logPath = this.dir+"/_webcentral_data/log";
		makePathSync(logPath, this.uid);

		this.logger = new Logger({path: logPath, base: "", uid: this.uid, gid: this.gid, deleteAfterDays: 21});
		
		let config = {};
		if (fs.existsSync(dir+"webcentral.ini")) {
			try {
				config = ini.parse(fs.readFileSync(dir+"webcentral.ini").toString());
			} catch(e) {
				this.logger.write("webcentral.ini error: "+e);
			}
		} else if (fs.existsSync(dir+"package.json")) {
			config = {
				command: ["npm", "start"],
			};
		}

		this.reload = config.reload || {};
		if (this.reload.timeout==null) this.reload.timeout = 10*60;
	
		if (this.reload.exclude) {
			if (typeof this.reload.exclude === 'string') this.reload.exclude = [this.reload.exclude];
			this.reload.exclude.push('_webcentral_data');
		} else {
			this.reload.exclude = ["_webcentral_data", "data", "log", "logs", "node_modules", "**/*.log", "**/.*"];
		}
		if (this.reload.include) {
			if (typeof this.reload.include === 'string') this.reload.include = [this.reload.include];
			this.reload.include.push('webcentral.ini');
		}
		this.reload.include = wildcardsToRegExp(this.reload.include);
		this.reload.exclude = wildcardsToRegExp(this.reload.exclude);
		this.watch('', false);
			
		if (this.reload.timeout > 0) {
			this.unusedInterval = setInterval(() => {
				let unused = new Date().getTime() - this.lastUse;
				if (unused > this.reload.timeout*1000) {
					this.logger.write("stopping due to inactivity");
					this.stop(true);
				}
			}, this.reload.timeout*1000 / 10);
		}

		this.rewritePairs = [];
		if (config.rewrite) { // an object containing [regexp] => [replacement] pairs
			for(let regexp in config.rewrite) {
				this.rewritePairs.push([new RegExp('^(?:'+regexp+')$'), config.rewrite[regexp]]);
			}
		}

		this.logRequests = config.log_requests || false;
		this.redirectHttp = config.redirect_http;
		this.redirectHttps = config.redirect_https || false;
		
		if (config.command || config.docker) {
			this.command = config.command == null ? [] : (typeof config.command === 'string' ? ['/bin/sh', '-c', config.command] : config.command);
			this.host = "localhost";
			this.docker = config.docker;
			this.environment = config.environment;
			getPort().then(port => {
				this.port = port;
				this.createProxy({target: {host: 'localhost', port}});
				this.runCommand();
			});
			this.handler = this.handleProxy;
			return; // started() will be called by runCommand()
		} else if (config.redirect) {
			this.redirect = config.redirect;
			this.logger.write("starting redirect to "+this.redirect);
			this.handler = this.handleRedirect;
		} else if (config.proxy) {
			this.logger.write("starting proxy for "+config.proxy);
			let domain = parseUrl(config.proxy).host;
			this.createProxy({target: config.proxy, changeOrigin: true, autoRewrite: true, protocolRewrite: true, cookieDomainRewrite: domain});
			this.handler = this.handleProxy;
		} else if (config.port) {
			let target = {
				host: config.host || 'localhost',
				port: config.port,
			};
			this.logger.write("starting forward to http://"+target.host+":"+target.port);
			this.createProxy({target});
			this.handler = this.handleProxy;
		} else if (config.socket_path) {
			let target = {
				socketPath: config.socket_path
			};
			this.logger.write("starting forward to socket "+target.socketPath);
			this.createProxy({target});
			this.handler = this.handleProxy;
		} else {
			this.logger.write("starting static file server");
			this.staticServer = serveStatic(dir+'/public', {extensions: ['html']});
			this.handler = this.handleStatic;
		}
		this.started();
	}

	watch(base, included) {
		this.watchers.push(fs.watch(this.dir+'/'+base, (type, file) => {
			if (this.changes) return;
			let path = base+file;
			if (this.reload.exclude && path.match(this.reload.exclude)) return;
			if (!included && this.reload.include && !path.match(this.reload.include)) return;
			this.changes = true;
			this.logger.write(`stopping due to ${type} for ${path}`);
			this.stop(true);
		}));
		for(let file of fs.readdirSync(this.dir+'/'+base)) {
			let path = base+file;
			if (this.reload.exclude && path.match(this.reload.exclude)) continue;
			try {
				if (!fs.lstatSync(this.dir+'/'+path).isDirectory()) continue;
			} catch(e) {
				this.logger.write(`file disappeared: ${path}`);
				continue;
			}
			this.watch(path+'/', included || !this.reload.include || path.match(this.reload.include));
		}
	}

	createProxy(opts) {
		this.proxy = httpProxy.createProxyServer({...opts, xfwd: true, ws: true});
		this.proxy.on('error', this.handleProxyError.bind(this));
	}

	handleProxyError(err, req, rsp) {
		let retry = req.proxy_retry = (req.proxy_retry||0) + 1;
		if (retry > 10 || req.method!=='GET') {
			this.handleError(err, req, rsp);
		}
		else {
			this.logger.write(`retrying after error ${req.method} ${req.url}: ${err}`);
			setTimeout(() => {
				this.proxy.proxyRequest(req, rsp);
			}, 500);
		}
	}

	runCommand() {
		this.logger.write("starting on port "+this.port);
		this.startTime = new Date().getTime();

		this.reachableInterval = setInterval(async () => {
			if ((await portReachable(this.port)) && this.queue) {
				this.logger.write("reachable on port "+this.port+" after "+(new Date().getTime() - this.startTime)+"ms");
				clearTimeout(this.reachableInterval);
				this.reachableInterval = null;
				this.started();
			}
		}, 200);

		let docker = this.docker;
		if (docker) {
			if (!docker.base) docker.base = "alpine";
			let commands = typeof docker.commands === 'string' ? [docker.commands] : (docker.commands || []);
			if (docker.packages) {
				let packages = typeof docker.packages === 'string' ? docker.packages : docker.packages.join(' ');
				commands.unshift(`if command -v apk > /dev/null ; then apk update && apk add --no-cache ${packages} ; else apt-get update && apt-get install --no-install-recommends --yes ${packages}; fi`);
			}
			commands = commands.map(s => "RUN "+(typeof s === 'string' ? s+"\n" : JSON.stringify(s)+"\n")).join("");

			let appDir = docker.app_dir || "/app";

			let dockerfile = `FROM ${docker.base}\n`;
			if (docker.mount_app_dir !== false) {
				dockerfile += `WORKDIR ${appDir}\n`;
			}
			dockerfile += commands;
			this.logger.write('build', dockerfile);

			let user;
			if (this.uid) {
				// We can't do a setuid/setgid, because that doesn't load supplementary groups like 'docker', causing
				// permission denied when connecting to the docker socket. Instead, we'll build as root, and then ask
				// 'docker run' to set the user for us.
				user = `--user=${this.uid}:${this.gid}`;
				this.dockerUid = this.uid;
				delete this.uid;
				delete this.gid;
			} else {
				user = `--user=${process.getuid()}:${process.getgid()}`;
			}

			let builder = this.process = childProcess.spawn("docker", ["build", "-q", "-"], this.getProcessOpts());
			let imageHash = "";
			builder.stdout.on('data', data => imageHash += data);
			builder.stderr.on('data', data => this.logger.write("build err", data));

			const buildError = (code) => {
				this.logger.write("build exited", code);
				if (code) {
					this.stop();
				} else {
					let httpPort = docker.http_port || 8000;
					let args = ["docker", "run", "--rm", "--mount", "type=bind,src=/etc/passwd,dst=/etc/passwd", "--mount", "type=bind,ro,src=/etc/group,dst=/etc/group", "-p", `${this.port}:${httpPort}`, user];

					let homeDir = '/tmp';
					if (docker.mount_app_dir !== false) {
						args.push("--mount", `type=bind,src=${this.dir},dst=${appDir}`);
						makePathSync(`${this.dir}/_webcentral_data/home`, this.dockerUid);
						homeDir = `${appDir}/_webcentral_data/home`;
					}

					let dockerEnv = this.environment || {};
					if (dockerEnv.PORT==null) dockerEnv.PORT = httpPort;
					if (dockerEnv.HOME==null) dockerEnv.HOME = homeDir;

					// Add the environment variables as arguments to Docker
					for(let k in dockerEnv) {
						args.push('--env');
						args.push(`${k}=${dockerEnv[k]}`);
					}
					// Don't add the environment variables when executing Docker itself
					this.environment = {};

					// Add any extra mounts as docker arguments
					for(let dst of docker.mounts || []) {
						if (dst[0] != '/') dst = joinPath(appDir, dst);
						let src = joinPath(this.dir, '_webcentral_data', 'mounts', dst);
						makePathSync(src, this.dockerUid);
						args.push('--mount');
						args.push(`type=bind,src=${src},dst=${dst}`);
					}

					args.push(imageHash.trim());
					this.startProcess(...args);
				}
			};

			builder.on('close', buildError);
			builder.on('error', buildError);

			builder.stdin.on('error', function(){});
			builder.stdin.write(dockerfile);
			builder.stdin.end();
			
		} else if (Project.firejail) {
			this.startProcess(
				"firejail",
				"--noprofile",
				"--private="+this.dir,
				"--private-dev",
				"--private-etc=group,hostname,localtime,nsswitch.conf,passwd,resolv.conf,alternatives",
				"--private-tmp",
				"--seccomp",
				"--caps.drop=all",
				"--disable-mnt",
				"--shell=none"
			);
		} else {
			this.startProcess();
		}
	}

	getProcessOpts() {
		let opts = {
			env: Object.assign({}, this.environment, {
				PORT: this.port,
				PATH: process.env.PATH,
			}),
			cwd: this.dir,
		};
		if (this.uid) {
			opts.uid = this.uid;
			opts.gid = this.gid;
		}
		opts.env.HOME = childProcess.execSync(`getent passwd ${(0|this.uid) || process.getuid()} | cut -d: -f6`).toString().trim();
		return opts;
	}

	startProcess(...args) {
		if (this.stopped) return;

		if (this.command) {
			if (typeof this.command === 'string') this.command = ['/bin/sh', '-c', this.command];
			args = args.concat(this.command);
		}
		this.logger.write(`start process: '${args.join("' '")}'`);

		this.process = childProcess.spawn(args[0], args.slice(1), this.getProcessOpts());

		this.process.stdout.on('data', data => this.logger.write("out", data));
		this.process.stderr.on('data', data => this.logger.write("err", data));

		const processError = (code) => {
			this.logger.write("process exited with code "+code);
			this.process = null;
			this.stop();
		};

		this.process.on('close', processError);
		this.process.on('error', processError);
	}

	started() {
		let queue = this.queue;
		this.queue = null;
		for(let opts of queue) {
			this.handle(opts);
		}
	}

	stop(moveQueue) {
		if (this.stopped) return;
		this.logger.write("stopping");
		this.stopped = true;
		if (all[this.dir]===this) {
			delete all[this.dir];
		}
		clearTimeout(this.unusedInterval);
		clearTimeout(this.reachableInterval);
		for(let watcher of this.watchers) watcher.close();

		if (this.queue && this.queue.length) {
			if (moveQueue) {
				const replacement = Project.get(this.dir);
				for(let opts of this.queue) {
					replacement.handle(opts);
				}
			} else {
				for(let opts of this.queue) {
					if (opts.socket) opts.socket.destroy();
					else this.handleError("cannot start application", opts.req, opts.rsp);
				}
			}
			this.queue = null;
		}

		let process = this.process;
		if (process) {
			process.kill();
			setTimeout(() => {
				if (process === this.process) process.kill(9);
			}, 2000);
		}

		if (this.proxy) {
			this.proxy.close();
		}
	}

	handleProxy(opts) {
		if (opts.socket) {
			this.proxy.ws(opts.req, opts.socket, opts.head);
		} else {
			this.proxy.web(opts.req, opts.rsp);
		}
	}

	handleStatic({req, rsp}) {
		this.staticServer(req, rsp, () => {
			this.logger.write(`static ${req.method} ${req.url} failed`);
			rsp.writeHead(404, "No such file");
			rsp.end("No such file");
		});
	}

	handleRedirect({req,rsp}) {
		rsp.writeHead (301, {'Location': this.redirect + req.url});
		rsp.end();
	}

	handle(opts) {
		this.lastUse = new Date().getTime();
		if (this.queue) {
			this.queue.push(opts);
			return;
		}
		let req = opts.req;
		for(let [regexp,replacement] of this.rewritePairs) {
			let url = req.url;
			if (url.search(regexp)>=0) {
				req.url = url.replace(regexp, replacement);
				this.logger.write(`rewrote ${url} to ${req.url} due to ${regexp}`);
				let match = req.url.match(/^webcentral:\/\/(.*?)(\/.*)$/);
				if (match) {
					// Hand the request over to a different webcentral project
					req.headers.host = match[1];
					req.url = match[2];
					return index.handleRequest(req, opts.rsp);
				}
				break; // stop replacing after a match
			}
		}

		this.handler(opts);
	}

	handleError(err,req,rsp) {
		this.logger.write(`error for ${req.method} ${req.url}: ${err}`);
		this.stop();
		rsp.writeHead(500, {'Content-Type': 'text/plain'});
		rsp.write('Webcentral upstream error: '+err);
		rsp.end();
	}
}


