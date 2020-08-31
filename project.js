'use strict';

const childProcess = require('child_process');
const fs = require('fs');
const getPort = require('get-port');
const httpProxy = require('http-proxy');
const net = require('net');
const serveStatic = require('serve-static');
const toml = require('toml');

const Logger = require('./logger');


function portReachable(port) {
	return new Promise(function(resolve) {
		const socket = new net.Socket();

		function onError(){
			socket.destroy();
			resolve(false);
		}

		socket.setTimeout(250);
		socket.on('error', onError);
		socket.on('timeout', onError);

		socket.connect(port, 'localhost', function(){
			socket.write("HEAD / HTTP/1.1\nHost: example.com\n\n");
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
		this.project = dir.split('/').pop();
		this.queue = [];
		this.lastUse = new Date().getTime();
		this.watchers = [];

		if (process.getuid()==0) { // running as root -- process should run as owner of project directory
			let stat = fs.statSync(this.dir);
			this.uid = stat.uid;
			this.gid = stat.gid;
		}

		this.logger = new Logger({path: this.dir+"/log", base: "webcentral_", uid: this.uid, gid: this.gid, deleteAfterDays: 21});
		
		let config;
		if (fs.existsSync(dir+"package.json")) {
			config = {
				command: ["npm", "start"],
			};
		} else if (fs.existsSync(dir+"webcentral.toml")) {
			config = {};
			try {
				config = toml.parse(fs.readFileSync(dir+"webcentral.toml"));
			} catch(e) {
				this.logger.write("webcentral.toml error: "+e);
			}
		}

		this.reload = (config && config.reload) || {};
		if (this.reload.timeout==null) this.reload.timeout = 10*60;
	
		if (this.reload.exclude) {
			if (typeof this.reload.exclude === 'string') this.reload.exclude = [this.reload.exclude];
			this.reload.exclude.push('log');
		} else {
			this.reload.exclude = ["data", "log", "logs", "node_modules", "**/*.log", "**/.*"];
		}
		if (this.reload.include) {
			if (typeof this.reload.include === 'string') this.reload.include = [this.reload.include];
			this.reload.include.push('webcentral.yaml');
		}
		this.reload.include = wildcardsToRegExp(this.reload.include);
		this.reload.exclude = wildcardsToRegExp(this.reload.exclude);
		this.watch('', false);
			
		if (this.reload.timeout) {
			this.unusedInterval = setInterval(() => {
				let unused = new Date().getTime() - this.lastUse;
				if (unused > this.reload.timeout*1000) {
					this.logger.write("stopping due to inactivity");
					this.stop(true);
				}
			}, this.reload.timeout*1000 / 10);
		}

		if (config) {
			if (config.command) {
				this.command = typeof config.command === 'string' ? ['/bin/sh', '-c', config.command] : config.command;
				this.host = "localhost";
				this.docker = config.docker;
				getPort().then(port => {
					this.port = port;
					this.createProxy({target: {host: 'localhost', port}});
					this.runCommand();
				});
				return; // started() will be called by runCommand()
			} else if (config.redirect) {
				this.redirect = config.redirect;
				this.logger.write("starting redirect to "+this.redirect);
				this.handle = this.handleRedirect;
			} else if (config.proxy) {
				this.logger.write("starting proxy for "+config.proxy);
				this.createProxy({target: config.proxy, changeOrigin: true, autoRewrite: true});
			} else if (config.command) {
				this.command = typeof config.command == 'string' ? ['/bin/sh', '-c', this.command] : config.command;
				this.host = "localhost";

			} else {
				let target = {
					host: config.host || 'localhost',
					port: config.port || 8080,
				};
				this.logger.write("starting forward to http://"+target.host+":"+target.port);
				this.createProxy({target});
			}
		} else {
			this.logger.write("starting static file server");
			this.staticServer = serveStatic(dir, {extensions: ['html']});
			this.handle = this.handleStatic;
		}
		this.started();
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
		this.proxy = httpProxy.createProxyServer(opts);
		this.proxy.on('error', this.handleError.bind(this));
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
		}, 50);

		let docker = this.docker;
		if (docker) {
			if (!docker.base) docker.base = "alpine";
			let run = typeof docker.run === 'string' ? [docker.run] : (docker.run || []);
			if (docker.packages) {
				let packages = typeof docker.packages === 'string' ? docker.packages : docker.packages.join(' ');
				run.unshift(`if command -v apk &> /dev/null ; then apk update && apk add --no-cache ${packages} ; else apt-get update && apt-get install --no-install-recommends --yes ${packages}; fi`);
			}
			run = run.map(s => "RUN "+(typeof s === 'string' ? s : JSON.stringify(s)));

			let dockerfile = [
				`FROM ${docker.base}`,
				`WORKDIR /app`
			].concat(run).join("\n");
			this.logger.write('build', dockerfile);

			let user = '';
			if (this.uid) {
				// We can't do a setuid/setgid, because that doesn't load supplementary groups like 'docker', causing
				// permission denied when connecting to the docker socket. Instead, we'll build as root, and then ask
				// 'docker run' to set the user for us.
				user = `--user=${this.uid}:${this.gid}`;
				delete this.uid;
				delete this.gid;
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
					let args = ["docker", "run", "--rm", "-i", "--mount", `type=bind,src=${this.dir},dst=/app`, "-p", `${this.port}:8000`];
					if (user) args.push(user);
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
				"--private-etc=group,hostname,localtime,nsswitch.conf,passwd,resolv.conf",
				"--private-tmp",
				"--seccomp",
				"--shell=none"
			);
		} else {
			this.startProcess();
		}
	}

	getProcessOpts() {
		let opts = {
			env: {
				PORT: this.port,
				PATH: process.env.PATH,
			},
			cwd: this.dir,
		};
		if (this.uid) {
			opts.uid = this.uid;
			opts.gid = this.gid;
		}
		return opts;
	}

	startProcess(...args) {
		if (this.stopped) return;

		if (this.command) {
			if (typeof this.command === 'string') this.command = ['/bin/sh', '-c', this.command];
			args = args.concat(this.command);
		}
		this.logger.write("start process "+JSON.stringify(args));

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
					if (opts.socket) opts.socket.close();
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

	handle(opts) {
		if (this.queue) {
			this.queue.push(opts);
			return;
		}
		this.lastUse = new Date().getTime();
		if (opts.socket) this.proxy.ws(opts.req, opts.socket, opts.head);
		else this.proxy.web(opts.req, opts.rsp);
	}

	handleError(err,req,rsp) {
		this.logger.write('handling error: '+err);
		this.stop();
		rsp.writeHead(500, {'Content-Type': 'text/plain'});
		rsp.write('webcentral upstream error: '+err);
		rsp.end();
	}
}


