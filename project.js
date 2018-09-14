const expressHttpProxy = require('express-http-proxy');
const childProcess = require('child_process');
const getPort = require('get-port');
const net = require('net');

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
		this.queue = [];
		this.handleError = this.handleError.bind(this);
		getPort().then(port => {
			this.port = port;
			this.init();
		});
	}

	init() {
		console.log(this.dir, 'on port', this.port);
		this.startTime = new Date().getTime();
		this.proxy = expressHttpProxy("localhost:"+this.port);

		this.interval = setInterval(async () => {
			if ((await portReachable(this.port)) && this.queue) {
				console.log('reachable', this.port);
				clearTimeout(this.interval);
				this.interval = null;
				let queue = this.queue;
				this.queue = null;
				for(let {req,rsp} of queue) {
					this.handle(req,rsp);
				}
			}
		}, 100);

		this.process = childProcess.spawn("firejail", ["--noprofile", "--private="+this.dir, "npm", "start"], {
			env: {PORT: this.port, PATH: "/bin:/usr/bin:/usr/local/bin"},
		});

		this.process.stdout.on('data', (data) => {
			console.log(this.dir, data.toString());
		});

		this.process.stderr.on('data', (data) => {
			console.log(this.dir, data.toString());
		});

		const processError = (code) => {
			console.log("process exit", this.dir, code);
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
		if (this.interval) clearTimeout(this.interval);
		let process = this.process;
		if (process) {
			process.kill();
			setTimeout(() => {
				if (process === this.process) process.kill(9);
			}, 2000);
		}
		if (this.queue) {
			for(let {req,rsp} of this.queue) {
				this.handleError(req,rsp);
			}
		}
	}

	handle(req,rsp) {
		if (this.queue) {
			this.queue.push({req,rsp});
			return;
		}
		this.proxy(req, rsp, this.handleError);
	}

	handleError(req,rsp) {
		console.log('handleError');
		this.stop();
		rsp.status(500).end("node-central upstream didn't respond");
	}
}
