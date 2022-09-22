//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * Converts betwee SSH-protocol address string and IP address strings.
 */
export class IPAddressConversions {
	/**
	 * Converts from an SSH-protocol address string to an IP address string.
	 */
	public static fromSshAddress(address?: string): string {
		if (!address) {
			// SSH uses an empty address to indicate "both IPv4-any and IPv6-any".
			// While this just returns the IPv4-any address, the default
			// TCP listener factory treats this value as dual-mode anyway,
			// meaning there's no way to actually listen on only IPv4-any.
			// It would be strange for an application to actually want to exclude
			// IPv6 like that, so this should be a reasonable limitation of this library.
			return '0.0.0.0';
		} else if (address === 'localhost') {
			// SSH uses a "localhost" address to indicate "both IPv4-loopback and
			// IPv6-loopback", while this just returns the IPv4-loopback address.
			// The default TCP listener factory treats this value as dual-mode anyway.
			return '127.0.0.1';
		} else {
			return address;
		}
	}

	/**
	 * Converts from an IP Address to an SSH-protocol address string.
	 */
	public static toSshAddress(ipAddress: string): string | null {
		if (!ipAddress) {
			return null;
		} else if (ipAddress === '0.0.0.0') {
			return '';
		} else if (ipAddress === '127.0.0.1') {
			return 'localhost';
		} else {
			return ipAddress;
		}
	}
}
