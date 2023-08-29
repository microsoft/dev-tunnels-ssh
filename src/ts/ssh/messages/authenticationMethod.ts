//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * Defines constants for standard authentication methods.
 */
export const enum AuthenticationMethod {
	none = 'none',
	publicKey = 'publickey',
	password = 'password',
	hostBased = 'hostbased',
	keyboardInteractive = 'keyboard-interactive',
}
