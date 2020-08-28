const childProcess = require('child_process');
const getPort = require('get-port');
const net = require('net');
const httpProxy = require('http-proxy');
const fs = require('fs');
const path = require('path');
const nodeStatic = require('node-static');

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

const all = {};

module.exports = class Project {

	static get(dir) {
		return all[dir] = all[dir] || new Project(dir);
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

		this.logger = new Logger({path: this.dir+"/log", base: "node-central_", uid: this.uid, gid: this.gid, deleteAfterDays: 21});
		
		this.unusedInterval = setInterval(() => {
			let unused = new Date().getTime() - this.lastUse;
			if (unused > 10*60*1000) {
				this.logger.write("stopping due to inactivity");
				this.stop(true);
			}
		}, 60*1000);

		this.watch(dir);

		let config;
		if (fs.existsSync(dir+"package.json")) {
			config = {
				command: ["npm", "start"],
			};
		} else if (fs.existsSync(dir+"node-central.json")) {
			config = {};
			try {
				config = JSON.parse(fs.readFileSync(dir+"node-central.json"));
			} catch(e) {
				this.logger.write("node-central.json error: "+e);
			}
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
			this.staticServer = new nodeStatic.Server(dir);
			this.handle = this.handleStatic;
		}
		this.started();
	}

	handleStatic({req, rsp}) {
		this.staticServer.serve(req, rsp, (err,result) => {
			if (err) {
				this.logger.write(`Static ${req.method} ${req.url}: ${err.message}`);
				rsp.writeHead(err.status, err.headers);
				rsp.end();
			}
		});
	}

	handleRedirect({req,rsp}) {
		rsp.writeHead (301, {'Location': this.redirect + req.url});
		rsp.end();
	}

	watch(dir) {
		this.watchers.push(fs.watch(dir, (type, file) => {
			if (file[0]==='.' || file.endsWith('.log')) return;
			if (this.changes) return;
			this.changes = true;
			this.logger.write('stopping due to '+type+'@'+path.join(dir,file));
			this.stop(true);
		}));
		fs.readdirSync(dir)
			.filter(name => name[0]!=='.' && ['data', 'log', 'logs', 'node_modules'].indexOf(name) < 0)
			.map(name => path.join(dir, name))
			.filter(file => fs.lstatSync(file).isDirectory())
			.forEach(file => this.watch(file));
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
			if (docker instanceof Array || typeof docker === 'string') docker = {base: "alpine", packages: docker};
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

			let builder = childProcess.spawn("docker", ["build", "-q", "-"], this.getProcessOpts());
			let tag = "";
			builder.stdout.on('data', data => tag += data);
			builder.stderr.on('data', data => this.logger.write("build err", data));

			const buildError = (code) => {
				this.logger.write("build exited", code);
				if (code) {
					this.stop();
				} else {
					this.startProcess("docker", "run", "--rm", "-i", "--mount", `type=bind,src=${this.dir},dst=/app`, "-p", `${this.port}:8000`, tag.trim());
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
		this.logger.write("ready to serve");
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
		rsp.write('node-central upstream error: '+err);
		rsp.end();
	}
}


