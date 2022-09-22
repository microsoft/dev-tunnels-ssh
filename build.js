//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

const child_process = require('child_process');
const os = require('os');
const fs = require('fs');
const glob = require('glob');
const moment = require('moment');
const path = require('path');
const util = require('util');
const yargs = require('yargs');

fs.readdir = util.promisify(fs.readdir);
fs.copyFile = util.promisify(fs.copyFile);
fs.rename = util.promisify(fs.rename);
fs.readFile = util.promisify(fs.readFile);
fs.writeFile = util.promisify(fs.writeFile);
fs.mkdir = util.promisify(fs.mkdir);
fs.unlink = util.promisify(fs.unlink);

yargs.version(false);
const buildGroup = 'Build Options:';
const testGroup = 'Test Options:';

yargs.option('verbosity', { desc: 'MSBuild verbosity', string: true, group: buildGroup });
yargs.option('configuration', {
	desc: 'MSBuild configuration',
	choices: ['Debug', 'Release'],
	group: buildGroup,
});
yargs.option('release', {
	desc: 'Use MSBuild Release configuration',
	boolean: true,
	group: buildGroup,
});
yargs.option('framework', {
	desc: 'Specify .net application framework',
	choices: ['netcoreapp2.1', 'netcoreapp3.1', 'net6.0', 'netstandard2.0', 'netstandard2.1'],
	group: buildGroup,
});
yargs.option('msbuild', {
	desc: 'Use MSBuild instead of dotnet CLI', // Signing requires msbuild
	boolean: true,
	group: buildGroup,
});

yargs.option('filter', { desc: 'Filter test cases', string: true, group: testGroup });
yargs.option('serial', { desc: 'Run tests serially (slower)', boolean: true, group: testGroup });
yargs.option('coverage', {
	desc: 'Collect code coverage when testing',
	boolean: true,
	group: testGroup,
});

const namespace = 'Microsoft.DevTunnels.Ssh';
const srcDir = path.join(__dirname, 'src');
const binDir = path.join(__dirname, 'out', 'bin');
const libDir = path.join(__dirname, 'out', 'lib');
const intermediateDir = path.join(__dirname, 'out', 'obj');
const packageDir = path.join(__dirname, 'out', 'pkg');
const packageJsonFile = path.join(__dirname, 'package.json');
const testResultsDir = path.join(__dirname, 'out', 'testresults');

function getPackageFileName(packageJson, buildVersion) {
	// '@scope/' gets converted to a 'scope-' prefix of the package filename.
	return `${packageJson.name.replace('@', '').replace('/', '-')}-${buildVersion}.tgz`;
}

yargs.command('build', 'Build C# and TypeScript code', async () => {
	await forkCommand('build-cs');
	await forkCommand('build-ts');
	await forkCommand('build-browsertest');
});

yargs.command('pack', 'Build C# and TypeScript packages', async () => {
	await forkCommand('pack-cs');
	await forkCommand('pack-ts');
});

yargs.command('test', 'Test C# and TypeScript code', async () => {
	await forkCommand('test-cs');
	await forkCommand('test-ts');
});

yargs.command('build-cs', 'Build C# code', async (yargs) => {
	const configuration = yargs.argv.configuration || (yargs.argv.release ? 'Release' : 'Debug');
	const verbosity = yargs.argv.verbosity || 'minimal';
	const command = yargs.argv.msbuild
		? `msbuild -nologo -v:${verbosity} -p:RestorePackages=false -p:Configuration=${configuration} -t:Build`
		: `dotnet build --nologo --no-restore -v ${verbosity} -c ${configuration}`;
	await executeCommand(__dirname, command);
});

yargs.command('build-ts', 'Build TypeScript code', async (yargs) => {
	const tsPackageNames = ['ssh', 'ssh-keys', 'ssh-tcp'];

	for (let packageName of tsPackageNames) {
		await linkLib('@microsoft/dev-tunnels-' + packageName, packageName);
	}

	await executeCommand(__dirname, `npm run --silent compile`);
	await executeCommand(__dirname, `npm run --silent eslint`);

	const buildVersion = await getBuildVersion();
	const majorMinorBuildVersion = buildVersion.replace(/\.(\d+)(-.*)?$/, '');
	const rootPackageJson = JSON.parse(await fs.readFile(path.join(__dirname, 'package.json')));

	// Update the package.json and README for each built package.
	for (let packageName of tsPackageNames) {
		const sourceDir = path.join(srcDir, 'ts', packageName);
		const targetDir = path.join(libDir, packageName);
		const builtPackageJsonFile = path.join(targetDir, 'package.json');
		const packageJson = JSON.parse(await fs.readFile(builtPackageJsonFile));

		packageJson.author = rootPackageJson.author;
		packageJson.version = buildVersion;
		packageJson.scripts = undefined;
		packageJson.main = './index.js';

		// Force the dependencies on other packages in this project to match the major.minor version.
		for (let packageName of Object.keys(packageJson.dependencies)) {
			if (packageName.startsWith(rootPackageJson.name)) {
				packageJson.dependencies[packageName] = `~` + majorMinorBuildVersion;
			}
		}

		await fs.writeFile(builtPackageJsonFile, JSON.stringify(packageJson, null, '\t'));

		await fs.copyFile(path.join(sourceDir, 'README.md'), path.join(targetDir, 'README.md'));
	}
});

yargs.command('build-browsertest', 'Build browser test bundle', async (yargs) => {
	const testLibDir = path.join(libDir, 'ssh-test');
	const skipModules = ['interopTests', 'portForwardingTests', 'tcpUtils', 'cli', 'bundle'];
	const testFiles = (await fs.readdir(testLibDir)).filter(
		(f) => f.endsWith('.js') && !skipModules.includes(f.replace(/\.js$/, '')),
	);
	const testFilesList = testFiles.join(' ');
	const excludeNodeAlgModules = (await fs.readdir(path.join(libDir, 'ssh', 'algorithms', 'node')))
		.filter((f) => f.endsWith('.js'))
		.map((f) => './node/' + path.basename(f, '.js'));
	const excludeModulesList = excludeNodeAlgModules.map((m) => `-u ${m}`).join(' ');
	const stubModulesList = ['fs', 'net'].map((m) => `-i ${m}`).join(' ');
	const browserifyCmd = path.join(__dirname, 'node_modules', 'browserify', 'bin', 'cmd.js');
	await executeCommand(
		testLibDir,
		`node "${browserifyCmd}" ${testFilesList} ${stubModulesList} ${excludeModulesList} ` +
			'-t brfs --debug -o ./bundle.js',
	);

	const testSrcDir = path.join(__dirname, 'test', 'ts', 'ssh-test');
	console.log('To run browser tests, browse to: ' + path.join(testSrcDir, 'test.html'));
});

yargs.command('pack-cs', 'Build C# NuGet packages', async (yargs) => {
	const configuration = yargs.argv.configuration || (yargs.argv.release ? 'Release' : 'Debug');
	const verbosity = yargs.argv.verbosity || 'minimal';
	const command = yargs.argv.msbuild
		? `msbuild -nologo -v:${verbosity} -p:RestorePackages=false -p:Configuration=${configuration} -t:Pack`
		: `dotnet pack --nologo --no-restore --no-build -v ${verbosity} -c ${configuration}`;
	await executeCommand(__dirname, command);
});

yargs.command('pack-ts', 'Build TypeScript npm packages', async (yargs) => {
	const buildVersion = await getBuildVersion();

	await mkdirp(packageDir);
	let packageFiles = [];

	for (let packageName of ['ssh', 'ssh-keys', 'ssh-tcp']) {
		const targetDir = path.join(libDir, packageName);
		await executeCommand(targetDir, `npm pack`);

		const packageJsonFile = path.join(targetDir, 'package.json');
		const packageJson = JSON.parse(await fs.readFile(packageJsonFile));
		const prefixedPackageFileName = getPackageFileName(packageJson, buildVersion);
		const packageFileName = prefixedPackageFileName.replace(/\w+-/, '');
		await fs.rename(
			path.join(targetDir, prefixedPackageFileName),
			path.join(packageDir, packageFileName),
		);
		packageFiles.push(packageFileName);
	}

	console.log(`Created packages [${packageFiles.join(', ')}] at ${packageDir}`);
});

yargs.command('publish-ts', 'Publish TypeScrypt npm packages', async (yargs) => {
	const buildVersion = await getBuildVersion();
	const packageJson = JSON.parse(await fs.readFile(packageJsonFile));
	const packageFileName = getPackageFileName(packageJson, buildVersion);
	const packageFilePath = path.join(packageDir, packageFileName);

	const publishCommand = `npm publish "${packageFilePath}"`;
	await executeCommand(__dirname, publishCommand);
});

yargs.command('test-cs', 'Run C# tests', async (yargs) => {
	await mkdirp(testResultsDir);

	const coverageSummaryFile = path.join(testResultsDir, 'CodeCoverage', 'Summary.txt');
	if (yargs.argv.coverage && fs.existsSync(coverageSummaryFile)) {
		await fs.unlink(coverageSummaryFile);
	}

	const configuration = yargs.argv.configuration || (yargs.argv.release ? 'Release' : 'Debug');

	// Updating the config file is the only way to control whether tests run in parallel.
	const testConfigFilesGlob = path.join(binDir, configuration) + '/**/xunit.runner.json';
	for (let testConfigFile of glob.sync(testConfigFilesGlob)) {
		const testConfig = JSON.parse(fs.readFileSync(testConfigFile));
		testConfig.parallelizeTestCollections = !yargs.argv.serial;
		fs.writeFileSync(testConfigFile, JSON.stringify(testConfig, null, '\t'));
	}

	// A date-time suffix will automatically be appended to the TRX filename.
	const trxBaseFileName = path.join(testResultsDir, 'SSH-CS.trx');

	const verbosity = yargs.argv.verbosity || 'normal';
	let command =
		'dotnet test --no-restore --no-build' +
		` -v ${verbosity}` +
		` -c ${configuration}` +
		` -p:CodeCoverage=${yargs.argv.coverage}` +
		` -l:"trx;LogFileName=${trxBaseFileName}"`;

	if (yargs.argv.framework) {
		command += ` --framework ${getTargetAppFramework(yargs.argv.framework)}`;
	}
	if (yargs.argv.filter) {
		command += ` --filter ${yargs.argv.filter}`;
	}

	await executeCommand(__dirname, command);

	if (yargs.argv.coverage && fs.existsSync(coverageSummaryFile)) {
		const coverageSummary = await fs.readFile(coverageSummaryFile);
		console.log(coverageSummary.toString());
	}
});

yargs.command('test-ts', 'Run TypeScript tests', async (yargs) => {
	await mkdirp(testResultsDir);

	const testResultsFile = path.join(
		testResultsDir,
		`SSH-TS_${moment().format('YYYY-MM-DD_HH-mm-ss-SSS')}.xml`,
	);
	const reporterConfig = {
		reporterEnabled: 'spec, mocha-junit-reporter',
		mochaJunitReporterReporterOptions: {
			mochaFile: testResultsFile,
		},
	};
	const reporterConfigFile = path.join(testResultsDir, 'mocha-multi-reporters.config');
	await fs.writeFile(reporterConfigFile, JSON.stringify(reporterConfig));

	let command =
		'npm run --silent mocha -- --reporter mocha-multi-reporters ' +
		`--reporter-options configFile="${reporterConfigFile}"`;
	if (yargs.argv.filter) {
		command += ` --grep /${yargs.argv.filter}/i`;
	}

	try {
		await executeCommand(__dirname, command);
	} finally {
		await fs.unlink(reporterConfigFile);
	}
});

yargs.command('bench-cs', 'Run C# benchmarks', async (yargs) => {
	const benchConfiguration = yargs.argv.configuration || (yargs.argv.debug ? 'Debug' : 'Release');
	const benchTarget = getTargetAppFramework(yargs.argv.framework);

	const benchmarkAssembly = path.join(
		binDir,
		benchConfiguration,
		'Ssh.Benchmark',
		benchTarget,
		namespace + '.Benchmark.dll',
	);
	const args = ['"' + benchmarkAssembly + '"'];
	if (yargs.argv.scenario) {
		args.push(yargs.argv.scenario);
	}
	await executeCommand(__dirname, 'dotnet', args);
});

yargs.command('bench-ts', 'Run TypeScript benchmarks', async (yargs) => {
	const benchmarkModule = path.join(libDir, 'ssh-bench', 'main.js');
	const args = [benchmarkModule];
	if (yargs.argv.scenario) {
		args.push(yargs.argv.scenario);
	}
	await executeCommand(__dirname, 'node', args);
});

function forkCommand(command) {
	const args = [command, ...process.argv.slice(3)];
	return new Promise((resolve) => {
		const options = { stdio: 'inherit', shell: true };
		const p = child_process.fork(process.argv[1], args, options);
		p.on('close', (code) => {
			if (code) process.exit(code);
			resolve();
		});
	});
}

function executeCommand(cwd, command, args) {
	if (!args) {
		const parts = command.split(' ');
		command = parts[0];
		args = parts.slice(1);
	}
	console.log(`${command} ${args.join(' ')}`);
	return new Promise((resolve, reject) => {
		const options = { cwd: cwd, stdio: 'inherit', shell: true };
		const p = child_process.spawn(command, args, options, (err) => {
			if (err) {
				err.showStack = false;
				reject(err);
			}
			resolve();
		});
		p.on('close', (code) => {
			if (code) process.exit(code);
			resolve();
		});
	});
}

async function mkdirp(dir) {
	try {
		await fs.mkdir(dir, { recursive: true });
	} catch (e) {
		if (e.code !== 'EEXIST') throw e;
	}
}

async function getBuildVersion() {
	const nbgv = require('nerdbank-gitversioning');
	const buildVersion = await nbgv.getVersion();
	return buildVersion.semVer2;
}

async function linkLib(packageName, dirName) {
	const libModuleFile = path.join(libDir, 'node_modules', packageName + '.js');
	await mkdirp(path.dirname(libModuleFile));
	await fs.writeFile(
		libModuleFile,
		'// Enable referencing this lib by package name instead of by relative path.\n' +
			`module.exports = require('../../${dirName}');\n`,
	);
}

function getTargetAppFramework(framework) {
	if (!framework || framework == 'netstandard2.1' || framework == 'netcoreapp3.1') {
		return 'netcoreapp3.1';
	} else if (framework == 'netstandard2.0' || framework == 'netcoreapp2.1') {
		return 'netcoreapp2.1';
	} else if (framework == 'net5.0') {
		return 'net5.0';
	} else if (framework == 'net6.0') {
		return 'net6.0';
	} else {
		throw new Error('Invalid target framework: ' + framework);
	}
}

yargs.parseAsync().catch(console.error);
