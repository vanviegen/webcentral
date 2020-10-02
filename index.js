'use strict';

const fs = require('fs');
const glob = require('glob').sync;
const path = require('path');

const Project = require('./project');

const isRoot = process.getuid()==0;
let configDir = isRoot ? "/var/lib/webcentral/" : canonDir(process.env.HOME+"/.webcentral");
let projectDir = isRoot ? "/home/*/webcentral-projects/" : canonDir(process.env.HOME+"/webcentral-projects");
let email = process.env.EMAIL || '';
let httpPort = 80;
let httpsPort = 443;
let redirectHttp = null;
let optionalWww = true;
let firejail = true;

let argv = process.argv.slice(2);
for(let i=0; i<argv.length; i++) {
	let [key,val] = argv[i].split('=');
	if (val==null && argv[i+1] && argv[i+1][0]!=='-') val = argv[++i];
	if (key=="--config") configDir = canonDir(val);
	else if (key=="--projects") projectDir = canonDir(val);
	else if (key=="--email") email = val;
	else if (key=="--http") httpPort = 0|val;
	else if (key=="--https") httpsPort = 0|val;
	else if (key=="--redirect-http") redirectHttp = (val==="true" || val==="yes");
	else if (key=="--optional-www") optionalWww = (val==="true" || val==="yes");
	else if (key=="--firejail") firejail = (val==="true" || val==="yes");
	else help("invalid option: "+key);
}

if (httpPort && httpsPort) {
	if (redirectHttp==null) redirectHttp = true;
} else {
	redirectHttp = false;
}

console.log(process.argv[1]+" --config="+configDir+" --projects="+projectDir+" --email="+email+ " --http="+httpPort+" --https="+httpsPort+" --redirect-http="+(redirectHttp?"true":"false")+" --optional-www="+(optionalWww?"true":"false")+" --firejail="+(firejail?"true":"false"));

if (httpsPort && (!email || !email.match(/@/))) {
	help("an email address should be specified");
}

if (!httpPort && !httpsPort) {
	help("at least one of http or https should be set");
}

Project.firejail = firejail;

function help(msg) {
	if (msg) console.error("Error: "+msg+"\n");
	console.log("usage: "+process.argv[0]+" --email domainAdmin@example.com");
	process.exit(1);
}

function canonDir(dir) {
	dir = path.resolve(dir);
	if (dir[dir.length-1]!=='/') dir += '/';
	return dir;
}

// Create data directory, if it doesn't exist
try {
	fs.mkdirSync(configDir);
} catch(e) {}


// Load bindings
let bindingsFile = configDir+"/bindings.json";
let bindings = {};
try {
	bindings = JSON.parse(fs.readFileSync(bindingsFile));
} catch(e) {}


let cachedProjectDirs = {};
function getProjectDir(domain) {
	if (cachedProjectDirs.hasOwnProperty(domain)) return cachedProjectDirs[domain];
	let result = realGetProjectDir(domain);
	if (result) {
		// Cache for 10s.
		cachedProjectDirs[domain] = result;
		setTimeout(function() {
			delete cachedProjectDirs[domain];
		}, 10000);
		return result;
	}
}

function realGetProjectDir(domain) {
	domain = domain.replace(/:\d+$/, '');
	if (typeof domain !== "string" || !domain.match(/^[a-zA-Z.0-9-:]+$/)) return;

	let candidates = glob(projectDir+domain+"/", {cwd: "/", absolute: true});
	if (!candidates.length) {
		if (!optionalWww) return;

		if (domain.substr(0,4)==='www.') domain = domain.substr(4);
		else domain = 'www.'+domain;
		
		candidates = glob(projectDir+domain+"/", {cwd: "/", absolute: true});
		if (!candidates.length) return;
	}

	let binding = bindings[domain];
	if (binding && candidates.indexOf(binding)>=0) {
		return binding;
	}

	binding = candidates[0];
	bindings[domain] = binding;
	fs.writeFile(bindingsFile, JSON.stringify(bindings), 'utf8', function(){});
	return binding;
}

function approveDomains(opts, certs, cb) {
	if (getProjectDir(opts.domain)) {
		cb(null, { options: opts, certs: certs });
	} else {
		cb(new Error(`unknown domain or project: ${opts.domain}`));
	}
}

let projects = {};

function handleRequest(req, rsp) {
	if (!req.headers.host) {
		console.error('no host', req.headers, req.path);
	}
	let projectDir = getProjectDir(req.headers.host);
	if (!projectDir) {
		rsp.writeHead(404, {'Content-Type': 'text/plain'});
		rsp.write(`Webcentral: no project can be found for ${req.headers.host}`);
		rsp.end();
		return;
	}

	Project.get(projectDir).handle({req, rsp});
}

function handleWebSocket(req, socket, head) {
	let projectDir = getProjectDir(req.headers.host);
	if (!projectDir) {
		socket.close();
		return;
	}
	Project.get(projectDir).handle({req, socket, head});
}
 

const greenlock = require('greenlock').create({
	version: 'draft-11',
	server: 'https://acme-v02.api.letsencrypt.org/directory',
	configDir: configDir+'acme/',
	email: email,
	agreeTos: true,
	approveDomains,
	communityMember: false,
	telemetry: false,
	debug: false,
	store: require('greenlock-store-fs'),
});

let servers = [];
if (httpsPort) {
	let server = require('https').createServer(greenlock.tlsOptions);
	servers.push(server);
	configureServer(server, httpsPort);
}

if (httpPort) {
	if (httpsPort && redirectHttp) {
		let server = require('http').createServer(greenlock.middleware(require('redirect-https')({port:httpsPort})))
		server.listen(httpPort);
		servers.push(server)
	} else {
		let server = require('http').createServer();
		configureServer(server, httpPort);
		servers.push(server);
	}
}
process.on('SIGTERM', () => {
	console.log('SIGTERM received');
	for(let server of servers) {
		server.close();
	}
	Project.stopAll();
});

function configureServer(server, port) {
	server.on('request', handleRequest);
	server.on('upgrade', handleWebSocket);
	server.listen(port);
}

exports.handleRequest = handleRequest;
