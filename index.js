'use strict';

const fs = require('fs');
const path = require('path');
const glob = require('tiny-glob/sync');

const Project = require('./project');

const isRoot = process.getuid()==0;
let configDir = isRoot ? "/var/lib/node-central/" : canonDir(process.env.HOME+"/.node-central");
let projectDir = isRoot ? "/home/*/public-node-projects/" : canonDir(process.env.HOME+"/public-node-projects");
let email = process.env.EMAIL || '';
let httpPort = 80;
let httpsPort = 443;

let argv = process.argv.slice(2);
for(let i=0; i<argv.length; i++) {
	let [key,val] = argv[i].split('=');
	if (val==null && argv[i+1] && argv[i+1][0]!=='-') val = argv[++i];
	if (key=="--config") configDir = canonDir(val);
	else if (key=="--projects") projectDir = canonDir(val);
	else if (key=="--email") email = val;
	else if (key=="--http") httpPort = 0|val;
	else if (key=="--https") httpsPort = 0|val;
	else help("invalid option: "+key);
}

if (!email || !email.match(/@/)) {
	help("an email address should be specified");
}

if (!httpPort && !httpsPort) {
	help("at least one of http or https should be set");
}

console.log(process.argv[1]+" --config="+configDir+" --projects="+projectDir+" --email="+email+ " --http="+httpPort+" --https="+httpsPort);


function help(msg) {
	if (msg) console.error("Error: "+msg+"\n");
	console.log("usage: "+process.argv[0]+" --email domainAdmin@example.com [--datadir /var/lib/node-central] [--projectdir '/home/*/public-node-projects']");
	process.exit(1);
}

function canonDir(dir) {
	let dir = fs.realpathSync(dir);
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



function getProjectDir(domain) {
	if (!domain.match(/^[a-zA-Z.-]+$/)) return;

	let candidates = glob(projectDir+domain+"/package.json", {
		cwd: "/",
		absolute: true,
		filesOnly: true,
		flush: true,
	}).map(s => path.dirname(s));

	if (!candidates.length) return;

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
		rsp.write('node-central no such project');
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

if (httpPort && httpsPort) {
	require('http').createServer(greenlock.middleware(require('redirect-https')({port:httpsPort}))).listen(httpPort);
}
const server = httpsPort ? require('https').createServer(greenlock.tlsOptions) : require('http').createServer();
server.on('request', handleRequest);
server.on('upgrade', handleWebSocket);
server.listen(httpsPort || httpPort);

