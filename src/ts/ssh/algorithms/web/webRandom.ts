//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';

export class WebRandom {
	public getBytes(buffer: Buffer): void {
		crypto.getRandomValues(buffer);
	}
}
