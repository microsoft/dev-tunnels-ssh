//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as packageJson from './package.json';
const packageName = packageJson.name.replace(/^@\w+\//, ''); // Strip scope from name.
const packageVersion = packageJson.version;

/**
 * Parses the SSH software name and version from the version string exchanged via the
 * initial packets sent between client and server.
 */
export class SshVersionInfo {
	/**
	 * Attempts to parse an SSH version string into a version info object.
	 */
	public static tryParse(versionString: string): SshVersionInfo | null {
		if (!versionString) {
			throw new TypeError('Version string expected.');
		}

		if (!versionString.startsWith('SSH-')) {
			return null;
		}

		const firstDashIndex = 3;
		const secondDashIndex = versionString.indexOf('-', firstDashIndex + 1);
		if (secondDashIndex <= 0) {
			return null;
		}

		const protocolVersion = versionString.substring(firstDashIndex + 1, secondDashIndex);
		if (!/^\d+\.\d+$/.test(protocolVersion)) {
			return null;
		}

		let name: string;
		let version: string | null;

		const nameAndVersion = versionString.substring(secondDashIndex + 1);
		const spaceIndex = nameAndVersion.indexOf(' ');
		const lastUnderscoreBeforeSpace = nameAndVersion.lastIndexOf(
			'_',
			spaceIndex >= 0 ? spaceIndex : nameAndVersion.length - 1,
		);

		if (lastUnderscoreBeforeSpace >= 0) {
			name = nameAndVersion.substring(0, lastUnderscoreBeforeSpace).replace(/_/g, ' ');

			// Ignore any non-digit characters after the version.
			version = nameAndVersion.substring(lastUnderscoreBeforeSpace + 1);
			for (let i = 0; i < version.length; i++) {
				const c = version[i];
				if (!(c >= '0' && c <= '9') && c !== '.') {
					version = version.substring(0, i);
					break;
				}
			}

			if (!/^\d+(\.\d+)*$/.test(version)) {
				version = null;
			}
		} else {
			name = nameAndVersion;
			version = null;
		}

		return new SshVersionInfo(versionString, protocolVersion, name, version);
	}

	/**
	 * Gets the version info for the current SSH library.
	 */
	public static getLocalVersion(): SshVersionInfo {
		const protocolVersion = '2.0';
		const versionString = `SSH-${protocolVersion}-${packageName}_${packageVersion}`;
		return new SshVersionInfo(versionString, protocolVersion, packageName, packageVersion);
	}

	private constructor(
		versionString: string,
		protocolVersion: string,
		name: string,
		version: string | null,
	) {
		this.versionString = versionString;
		this.protocolVersion = protocolVersion;
		this.name = name;
		this.version = version;
	}

	private readonly versionString: string;

	/** Gets the SSH protocol version, currently always "2.0". */
	public readonly protocolVersion: string;

	/** Gets the name of the SSH application or library. */
	public readonly name: string;

	/** Gets the version of the SSH application or library. */
	public readonly version: string | null;

	/** Returns the original SSH version string that was parsed. */
	public toString(): string {
		return this.versionString;
	}

	/**
	 * Gets a value indicating whether this version info represents some version of
	 * this library.
	 */
	public get isVsSsh() {
		return this.isVsSshCS || this.isVsSshTS;
	}

	private get isVsSshCS() {
		return this.name === 'Microsoft.VisualStudio.Ssh' || this.name === 'Microsoft.DevTunnels.Ssh';
	}

	private get isVsSshTS() {
		return this.name === 'vs-ssh' || this.name === 'dev-tunnels-ssh';
	}
}
