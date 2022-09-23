//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

export interface SshAlgorithm {
	/**
	 * Gets the name that uniquely identifies this algorithm in the context of the SSH protocol,
	 * including the key size and mode or other algorithm parameters. This name is used when
	 * negotiating algorithms between client and server.
	 */
	readonly name: string;
}
