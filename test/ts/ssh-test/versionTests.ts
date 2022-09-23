//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, slow, timeout, pending, params } from '@testdeck/mocha';

import { SshVersionInfo } from '@microsoft/dev-tunnels-ssh';

@suite
export class VersionTests {
	@test
	public async getLocalVersion() {
		const localVersion = SshVersionInfo.getLocalVersion();
		assert.equal(localVersion.protocolVersion, '2.0');
		assert.equal(localVersion.name, 'dev-tunnels-ssh');
		assert(localVersion.version);
		assert(/^\d+\.\d+\.\d+(-g[0-9a-z]+)?$/.test(localVersion.version!));
	}

	@test
	@params({ name: 'Microsoft.DevTunnels.Ssh', version: '3.0.0' })
	@params({ name: 'dev-tunnels-ssh', version: '3.0.0' })
	@params({ name: 'OpenSSH', version: '7.7.7' })
	@params({ name: 'OpenSSH_for_Windows', version: '7.7.7' })
	@params({ name: 'OpenSSH', version: '7.7.7', extra: 'x1 extra' })
	@params({ name: 'test', extra: 'extra' })
	@params.naming((p) => `parseVersion(${p.name},${p.version ?? ''},${p.extra ?? ''})`)
	public parseVersion({
		name,
		version,
		extra,
	}: {
		name: string;
		version?: string;
		extra?: string;
	}) {
		const test = `SSH-2.0-${name}${version || extra ? '_' : ''}${version}${extra ?? ''}`;
		const result = SshVersionInfo.tryParse(test);
		assert(result);
		assert.equal(result!.protocolVersion, '2.0');
		assert.equal(result!.name, name.replace(/_/g, ' '));
		assert.equal(result!.version, version ?? null);
		assert.equal(result?.toString(), test);
	}
}
