// This enables the test key files to get bundled by browserify.
// Expressions in this file must be STATIC so they can be parsed by `brfs`
// See https://github.com/browserify/brfs

const fs = require('fs');

// prettier-ignore
export = {
	'private-rsa2048-jwk': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa2048-jwk.txt'),
	'private-rsa2048-pkcs1': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa2048-pkcs1.txt'),
	'private-rsa2048-pkcs1-pw': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa2048-pkcs1-pw.txt'),
	'private-rsa2048-pkcs8': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa2048-pkcs8.txt'),
	'private-rsa2048-pkcs8-pw': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa2048-pkcs8-pw.txt'),
	'private-rsa2048-openssh': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa2048-openssh.txt'),
	'private-rsa2048-openssh-pw': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa2048-openssh-pw.txt'),
	'private-rsa2048-ssh2': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa2048-ssh2.txt'),
	'private-rsa2048-ssh2-pw': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa2048-ssh2-pw.txt'),
	'public-rsa2048-ssh': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-rsa2048-ssh.txt'),
	'public-rsa2048-ssh2': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-rsa2048-ssh2.txt'),
	'public-rsa2048-jwk': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-rsa2048-jwk.txt'),
	'public-rsa2048-pkcs1': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-rsa2048-pkcs1.txt'),
	'public-rsa2048-pkcs8': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-rsa2048-pkcs8.txt'),
	'private-rsa4096-jwk': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa4096-jwk.txt'),
	'private-rsa4096-pkcs1': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa4096-pkcs1.txt'),
	'private-rsa4096-pkcs8': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa4096-pkcs8.txt'),
	'private-rsa4096-openssh': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa4096-openssh.txt'),
	'private-rsa4096-ssh2': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-rsa4096-ssh2.txt'),
	'public-rsa4096-ssh': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-rsa4096-ssh.txt'),
	'public-rsa4096-ssh2': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-rsa4096-ssh2.txt'),
	'public-rsa4096-jwk': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-rsa4096-jwk.txt'),
	'public-rsa4096-pkcs1': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-rsa4096-pkcs1.txt'),
	'public-rsa4096-pkcs8': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-rsa4096-pkcs8.txt'),
	'private-ecdsa384-sec1': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-ecdsa384-sec1.txt'),
	'private-ecdsa384-sec1-pw': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-ecdsa384-sec1-pw.txt'),
	'private-ecdsa384-pkcs8': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-ecdsa384-pkcs8.txt'),
	'private-ecdsa384-pkcs8-pw': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-ecdsa384-pkcs8-pw.txt'),
	'private-ecdsa384-openssh': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-ecdsa384-openssh.txt'),
	'private-ecdsa384-openssh-pw': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-ecdsa384-openssh-pw.txt'),
	'private-ecdsa384-jwk': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-ecdsa384-jwk.txt'),
	'public-ecdsa384-ssh': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-ecdsa384-ssh.txt'),
	'public-ecdsa384-pkcs8': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-ecdsa384-pkcs8.txt'),
	'public-ecdsa384-jwk': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-ecdsa384-jwk.txt'),
	'private-ecdsa521-sec1': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-ecdsa521-sec1.txt'),
	'private-ecdsa521-pkcs8': fs.readFileSync(__dirname + '/../../../test/data/testkey-private-ecdsa521-pkcs8.txt'),
	'public-ecdsa521-ssh': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-ecdsa521-ssh.txt'),
	'public-ecdsa521-pkcs8': fs.readFileSync(__dirname + '/../../../test/data/testkey-public-ecdsa521-pkcs8.txt'),
};
