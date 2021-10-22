'use strict';

const fs = require('fs');
const glob = require('glob').sync;


class Logger {
	constructor(opts) {
		Object.assign(this, opts);
		if (!this.path) throw new Error("path is a required option");
		if (!this.base) this.base = "";
	}

	write(topic, msg) {
		if (msg!=null) msg = `[${topic}] ${(msg+'').trim()}`;
		else {
			msg = (topic+'').trim();
			topic = '';
		}

		if (!msg) return;

		let [date,time] = new Date().toISOString().split('.')[0].split('T');
		if (date !== this.prevDate) {
			this.prevDate = date;
			this.open(date);
		}

		let prefix = "\n" + " ".repeat(9 + (topic.length ? topic.length+3 : 0))
		
		fs.write(this.fd, `${time} ${msg.replace(/\n/g, prefix)}\n`, () => {});
	}

	open(date) {
		if (this.fd) fs.close(this.fd, () => {});
		let filename = `${this.path}/${this.base}${date}.log`;
		this.fd = fs.openSync(filename, 'a+', 0o660);
		if (!this.fd) throw new Error('Cannot open log file: '+filename);
		if (this.uid) fs.chownSync(filename, this.uid, this.gid);

		if (this.deleteAfterDays>0) {
			let now = new Date().getTime();
			for(let file of glob(`$(this.path)/${this.base}*.log`, {absolute: true, filesOnly: true})) {
				let stats = fs.statSync(file);
				if (now - new Date(stats.mtime).getTime() > this.deleteAfterDays*24*60*60*1000) {
					fs.unlink(existing[i], () => {});
				}
			}
		}
	}

	static getDate() {
	    var d = new Date(),
	        month = '' + (d.getMonth() + 1),
	        day = '' + d.getDate(),
	        year = d.getFullYear();

	    if (month.length < 2) 
	        month = '0' + month;
	    if (day.length < 2) 
	        day = '0' + day;

	    return [year, month, day].join('-');
	}
}

module.exports = Logger;


