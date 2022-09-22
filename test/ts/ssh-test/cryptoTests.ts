//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, pending, slow, timeout, params } from '@testdeck/mocha';
import {
	SshAlgorithms,
	KeyPair,
	formatBuffer,
	MessageSigner,
	MessageVerifier,
} from '@microsoft/dev-tunnels-ssh';

@suite
@slow(200)
export class CryptoTests {
	@test
	@slow(5000)
	@timeout(10000)
	@params({ kexAlg: 'diffie-hellman-group14-sha256' })
	@params({ kexAlg: 'diffie-hellman-group16-sha512' })
	@params({ kexAlg: 'ecdh-sha2-nistp521' })
	@params({ kexAlg: 'ecdh-sha2-nistp384' })
	@params({ kexAlg: 'ecdh-sha2-nistp256' })
	@params.naming((p) => `keyExchange(${p.kexAlg})`)
	public async keyExchange({ kexAlg }: { kexAlg: string }) {
		const alg = Object.values(SshAlgorithms.keyExchange).find((a) => a?.name === kexAlg)!;
		assert(alg);

		const kexA = await alg.createKeyExchange();
		const kexB = await alg.createKeyExchange();

		const exchangeA = await kexA.startKeyExchange();
		const exchangeB = await kexB.startKeyExchange();

		const secretA = await kexA.decryptKeyExchange(exchangeB);
		const secretB = await kexB.decryptKeyExchange(exchangeA);

		assert(secretB.equals(secretA), 'key exchange secret');
	}

	@test
	@slow(5000)
	@timeout(10000)
	@params({ pkAlg: 'rsa-sha2-256', keySize: 1024 })
	@params({ pkAlg: 'rsa-sha2-512', keySize: 2048 })
	@params({ pkAlg: 'rsa-sha2-512', keySize: 4096 })
	@params({ pkAlg: 'ecdsa-sha2-nistp256' })
	@params({ pkAlg: 'ecdsa-sha2-nistp384' })
	@params({ pkAlg: 'ecdsa-sha2-nistp521' })
	@params.naming((p) => `signVerify(${p.pkAlg})`)
	public async signVerify({ pkAlg, keySize }: { pkAlg: string; keySize?: number }) {
		const alg = Object.values(SshAlgorithms.publicKey).find((a) => a?.name === pkAlg)!;
		assert(alg);

		const keyPair = await alg.generateKeyPair(keySize);

		const data = Buffer.from('test');
		const signer = alg.createSigner(keyPair);
		const signature = await signer.sign(data);
		assert(signature, 'signing with key pair');

		const verifier = alg.createVerifier(keyPair);
		const verified = await verifier.verify(data, signature);
		assert(verified, 'verifying with key pair');
	}

	@test
	@params({ encAlg: 'aes256-ctr' })
	@params({ encAlg: 'aes256-gcm@openssh.com' })
	@params.naming((p) => `encryptDecrypt(${p.encAlg})`)
	public async encryptDecrypt({ encAlg }: { encAlg: string }) {
		const alg = Object.values(SshAlgorithms.encryption).find((a) => a?.name === encAlg)!;
		assert(alg);

		const key = Buffer.alloc(alg.keyLength);
		const iv = Buffer.alloc(alg.blockLength);

		const random = SshAlgorithms.random;
		random.getBytes(key);
		random.getBytes(iv);

		const cipher = await alg.createCipher(true, key, iv);
		const decipher = await alg.createCipher(false, key, iv);

		const plaintext = Buffer.alloc(3 * alg.blockLength);
		plaintext.fill(9);

		const ciphertext = await cipher.transform(plaintext);
		assert.equal(ciphertext.length, plaintext.length, 'encrypted length');
		assert(!ciphertext.equals(plaintext), 'encrypted data');

		const signer = <MessageSigner>(<unknown>cipher);
		const verifier = <MessageVerifier>(<unknown>decipher);
		if (signer.authenticatedEncryption) {
			const tag = await signer.sign(plaintext);
			await verifier.verify(ciphertext, tag);
		}

		const plaintext2 = await decipher.transform(ciphertext);
		assert(plaintext2.equals(plaintext), 'decrypted data');
	}

	@test
	@params({ hmacAlg: 'hmac-sha2-256' })
	@params({ hmacAlg: 'hmac-sha2-512' })
	@params({ hmacAlg: 'hmac-sha2-256-etm@openssh.com' })
	@params({ hmacAlg: 'hmac-sha2-512-etm@openssh.com' })
	@params.naming((p) => `hmac(${p.hmacAlg})`)
	public async hmac({ hmacAlg }: { hmacAlg: string }) {
		const alg = Object.values(SshAlgorithms.hmac).find((a) => a?.name === hmacAlg)!;
		assert(alg);

		const key = Buffer.alloc(alg.keyLength);

		const random = SshAlgorithms.random;
		random.getBytes(key);

		const signer = await alg.createSigner(key);
		const verifier = await alg.createVerifier(key);

		const data = Buffer.alloc(16);
		data.fill(9);

		const signature = await signer.sign(data);
		assert.equal(signature.length, alg.digestLength, 'digest length');

		const verified = await verifier.verify(data, signature);
		assert(verified, 'verify');
	}
}
