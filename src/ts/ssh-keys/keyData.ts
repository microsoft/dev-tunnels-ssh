//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * Encapsulates formatted (serialized) key data and metadata.
 */
export class KeyData {
	/**
	 * The key type; the use of this property depends on the encoding. In PEM encoding,
	 * the key type is in the BEGIN and END markers.
	 */
	public keyType: string;

	/**
	 * Optional headers containing key metadata. In PEM encoding, the headers appear in
	 * plaintext before the base64-encoded key.
	 */
	public headers = new Map<string, string>();

	/**
	 * Formatted key bytes.
	 */
	public data: Buffer;

	private static readonly beginRegex = /^-+ *BEGIN (\w+( \w+)*) *-+$/;
	private static readonly endRegex = /^-+ *END (\w+( \w+)*) *-+$/;
	private static readonly headerRegex = /^([\w-]+): (.*)$/;

	public constructor(keyType?: string, data?: Buffer) {
		this.keyType = keyType ?? '';
		this.data = data ?? Buffer.alloc(0);
	}

	public static tryDecodePem(input: string): KeyData | null {
		const lines = input.split('\n').map((line) => line.trimRight());
		while (lines.length > 0 && lines[lines.length - 1].length === 0) {
			lines.splice(lines.length - 1, 1);
		}

		const beginMatch = lines[0].match(KeyData.beginRegex);
		const endMatch = lines[lines.length - 1].match(KeyData.endRegex);
		if (!beginMatch || !endMatch) {
			return null;
		}

		const keyType = beginMatch[1];
		if (endMatch[1] !== keyType) {
			return null;
		}

		let headers = new Map<string, string>();
		let i = 1;
		if (lines[i].includes(':')) {
			for (; i < lines.length - 1 && lines[i].length > 0; i++) {
				const headerMatch = lines[i].match(this.headerRegex);
				if (headerMatch) {
					const name = headerMatch[1];
					let value = headerMatch[2];
					while (value.endsWith('\\')) {
						value = value.substr(0, value.length - 1);
						value += lines[++i];
					}

					headers.set(name, value);
				}
			}
		}

		while (lines[i].length === 0) {
			i++;
		}

		let base64Data = lines.slice(i, lines.length - 1).join('');

		let data: Buffer;
		try {
			data = Buffer.from(base64Data, 'base64');
		} catch (e) {
			return null;
		}

		const keyData = new KeyData();
		keyData.keyType = keyType;
		keyData.headers = headers;
		keyData.data = data;
		return keyData;
	}

	public static tryDecodePemBytes(input: Buffer): KeyData | null {
		const hyphen = '-'.charCodeAt(0);
		if (input.length < 3 || input[0] !== hyphen || input[1] !== hyphen || input[2] !== hyphen) {
			return null;
		}

		let inputString: string;
		try {
			inputString = input.toString('utf8');
		} catch (e) {
			return null;
		}

		return KeyData.tryDecodePem(inputString);
	}

	public encodePem(): string {
		let s = `-----BEGIN ${this.keyType}-----\n`;

		for (let [name, value] of this.headers) {
			// TODO: Wrap the value with \ if it's long.
			s += `${name}: ${value}\n`;
		}

		if (this.headers.size > 0) {
			s += '\n';
		}

		const dataBase64 = this.data.toString('base64');

		const lineLength = 64;
		for (let offset = 0; offset < dataBase64.length; offset += lineLength) {
			s += dataBase64.substr(offset, Math.min(lineLength, dataBase64.length - offset)) + '\n';
		}

		s += `-----END ${this.keyType}-----\n`;
		return s;
	}

	public encodePemBytes(): Buffer {
		return Buffer.from(this.encodePem(), 'utf8');
	}

	public encodeSshPublicKey(): string {
		const comment = this.headers.get('Comment');
		return (
			this.keyType + ' ' + this.data.toString('base64') + (comment ? ' ' + comment : '') + '\n'
		);
	}

	public encodeSshPublicKeyBytes(): Buffer {
		return Buffer.from(this.encodeSshPublicKey(), 'utf8');
	}
}
