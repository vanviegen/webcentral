'use strict';

const fs = require('fs');
const proxy = require('http-proxy');
const Project = require('./project');

const baseDir = process.argv[2] || __dirname;
const configFile = baseDir+"/_config.json";
const config = JSON.parse(fs.readFileSync(configFile));

if (!config || typeof config !== 'object') throw new Error(configFile+": invalid JSON object");
if (config.agreeTos!==true) throw new Error(configFile+": 'agreeTos' must be true");
if (!config.domain || !config.domain.match(/^[a-z0-9\-]+\.[a-z0-9\-.]+$/)) throw new Error(configFile+": 'domain' should contain a valid domain");
if (!config.email || !config.email.match(/@/)) throw new Error(configFile+": 'email' should contain a valid email address");

function getProjectDir(domain) {
	// check for domains you want to receive certificates for
	if (domain===config.domain) {
		var project = '_index';
	} else {
		let m = domain.match(/^([a-z0-9\-]+)\.(.*)$/,'');
		if (m && m[2]===config.domain) {
			project = m[1];
		}
	}
	if (!project) return;

	try	{
		project = fs.realpathSync(baseDir+'/'+project);
		if (fs.lstatSync(project).isDirectory()) return project;
	} catch(e) {}
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

	Project.get(projectDir).handle(req, rsp);
}
 

const greenlock = require('greenlock').create({
	// Let's Encrypt v2 is ACME draft 11
	version: 'draft-11',
 
	// Note: If at first you don't succeed, switch to staging to debug,
	// https://acme-staging-v02.api.letsencrypt.org/directory
	server: 'https://acme-v02.api.letsencrypt.org/directory',
	configDir: baseDir+'/_acme/',
	email: config.email,
	agreeTos: config.agreeTos,
	approveDomains,
	communityMember: false,
	telemetry: false,
	debug: false,
});

require('http').createServer(greenlock.middleware(require('redirect-https')())).listen(80);
require('https').createServer(greenlock.tlsOptions, handleRequest).listen(443);

