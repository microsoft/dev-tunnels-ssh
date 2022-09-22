//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { Random } from '@microsoft/dev-tunnels-ssh';

export class MockRandom implements Random {
	private valueIndex: number = 0;

	public constructor(...values: Buffer[]) {
		this.values = values;
	}

	public readonly values: Buffer[];

	public getBytes(buffer: Buffer): void {
		assert(this.valueIndex < this.values.length);
		assert.equal(this.values[this.valueIndex].length, buffer.length);

		this.values[this.valueIndex].copy(buffer);

		this.valueIndex++;
	}
}
