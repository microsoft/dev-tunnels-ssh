//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { SshAlgorithm } from './sshAlgorithm';

export interface CompressionAlgorithm extends SshAlgorithm {
	compress(data: Buffer): Buffer;
	decompress(data: Buffer): Buffer;
}
