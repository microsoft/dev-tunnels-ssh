//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

export interface ECCurve {
	shortName: string;
	name: string;
	oid: string;
	keySize: number;
}

/**
 * List of EC curves supported by the SSH ECDSA algorithm.
 */
export const curves: ECCurve[] = [
	{
		shortName: 'P-256',
		name: 'nistp256',
		oid: '1.2.840.10045.3.1.7',
		keySize: 256,
	},
	{
		shortName: 'P-384',
		name: 'nistp384',
		oid: '1.3.132.0.34',
		keySize: 384,
	},
	{
		shortName: 'P-521',
		name: 'nistp521',
		oid: '1.3.132.0.35',
		keySize: 521,
	},
];
