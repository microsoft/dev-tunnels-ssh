//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as crypto from 'crypto';
import { Buffer } from 'buffer';

export class NodeRandom {
	public getBytes(buffer: Buffer): void {
		const randomBytes = crypto.randomBytes(buffer.length);
		randomBytes.copy(buffer);
	}
}
