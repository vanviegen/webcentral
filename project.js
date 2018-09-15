const childProcess = require('child_process');
const getPort = require('get-port');
const net = require('net');
const httpProxy = require('http-proxy');

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
			socket.end();
			resolve(true);
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
		getPort().then(port => {
			this.port = port;
			this.init();
		});
		this.unusedInterval = setInterval(() => {
			let unused = new Date().getTime() - this.lastUse;
			if (unused > 10*60*1000) {
				console.log(this.project, 'stopping due to inactivity');
				this.stop();
			}
		}, 60*1000);
	}

	init() {
		console.log(this.project, 'starting on port', this.port);
		this.startTime = new Date().getTime();

		this.proxy = httpProxy.createProxyServer({target: {host: 'localhost', port: this.port}});
		this.proxy.on('error', this.handleError.bind(this));

		this.reachableInterval = setInterval(async () => {
			if ((await portReachable(this.port)) && this.queue) {
				console.log(this.project, "reachable on port", this.port, "after", (new Date().getTime() - this.startTime)+"ms");
				clearTimeout(this.reachableInterval);
				this.reachableInterval = null;
				let queue = this.queue;
				this.queue = null;
				for(let {req,rsp} of queue) {
					this.handle(req,rsp);
				}
			}
		}, 50);

		this.process = childProcess.spawn("firejail", ["--noprofile", "--private="+this.dir, "npm", "start"], {
			env: {PORT: this.port, PATH: "/bin:/usr/bin:/usr/local/bin"},
		});

		const logPrefix = this.project+": ";
		function log(data) {
			console.log(logPrefix + data.toString().replace(/\n/g, "\n"+logPrefix));
		}

		this.process.stdout.on('data', log);
		this.process.stderr.on('data', log);

		const processError = (code) => {
			console.log(this.project, "process exited with code", code);
			this.process = null;
			this.stop();
		};

		this.process.on('close', processError);
		this.process.on('error', processError);
	}

	stop() {
		if (this.stopped) return;
		this.stopped = true;
		if (all[this.dir]===this) {
			delete all[this.dir];
		}
		clearTimeout(this.unusedInterval);
		clearTimeout(this.reachableInterval);
		let process = this.process;
		if (process) {
			process.kill();
			setTimeout(() => {
				if (process === this.process) process.kill(9);
			}, 2000);
		}
		if (this.queue) {
			for(let {req,rsp} of this.queue) {
				this.handleError("flushing queue on stop", req, rsp);
			}
		}
	}

	handle(req,rsp) {
		if (this.queue) {
			this.queue.push({req,rsp});
			return;
		}
		this.lastUse = new Date().getTime();
		this.proxy.web(req, rsp);
	}

	handleError(err,req,rsp) {
		console.log(this.project, 'handling error', err);
		this.stop();
		rsp.writeHead(500, {'Content-Type': 'text/plain'});
		rsp.write('node-central upstream error: '+err);
		rsp.end();
	}
}
