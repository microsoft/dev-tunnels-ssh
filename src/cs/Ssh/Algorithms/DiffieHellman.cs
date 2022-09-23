// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public class DiffieHellman : KeyExchangeAlgorithm
{
	public const string DHGroup14Sha256 = "diffie-hellman-group14-sha256";
	public const string DHGroup16Sha512 = "diffie-hellman-group16-sha512";

	public DiffieHellman(string name, int keySizeInBits, string hashAlgorithmName)
		: base(name, keySizeInBits, hashAlgorithmName, HmacAlgorithm.GetHashDigestLength(hashAlgorithmName))
	{
	}

	public override IKeyExchange CreateKeyExchange()
	{
		HashAlgorithm hashAlgorithm;
		if (this.HashAlgorithmName == HmacAlgorithm.Sha512)
		{
			hashAlgorithm = SHA512.Create();
		}
		else if (this.HashAlgorithmName == HmacAlgorithm.Sha256)
		{
			hashAlgorithm = SHA256.Create();
		}
		else
		{
			throw new NotSupportedException(
				$"Hash algorithm not supported: {this.HashAlgorithmName}");
		}

		return new DiffieHellmanKex(this.KeySizeInBits, hashAlgorithm);
	}

	private class DiffieHellmanKex : IKeyExchange
	{
		// http://tools.ietf.org/html/rfc2412
		private const string Okley1024 = "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

		// http://tools.ietf.org/html/rfc3526
		private const string Okley2048 = "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
		private const string Okley4096 = "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";

		private readonly BigInteger p;
		private readonly BigInteger g;
		private readonly BigInteger x;

		private readonly HashAlgorithm hash;

		public DiffieHellmanKex(int keySizeInBits, HashAlgorithm hash)
		{
			if (hash == null) throw new ArgumentNullException(nameof(hash));

			this.hash = hash;

			switch (keySizeInBits)
			{
				case 1024:
					this.p = BigInteger.Parse(Okley1024, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
					break;
				case 2048:
					this.p = BigInteger.Parse(Okley2048, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
					break;
				case 4096:
					this.p = BigInteger.Parse(Okley4096, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
					break;
				default:
					throw new ArgumentException("Invalid key size", nameof(keySizeInBits));
			}

			this.g = new BigInteger(2);

			var bytes = new Buffer(80); // 80 * 8 = 640 bits
			SshAlgorithms.Random.GetBytes(bytes);
			this.x = BigInteger.Abs(new BigInteger(bytes.Array));
		}

		public int DigestLength => this.hash.HashSize / 8;

		public Buffer StartKeyExchange()
		{
			var y = BigInteger.ModPow(this.g, this.x, this.p);
			var exchangeValue = ((BigInt)y).ToBuffer();
			return exchangeValue;
		}

		public Buffer DecryptKeyExchange(Buffer exchangeValue)
		{
			var pvr = (BigInteger)new BigInt(exchangeValue);
			var z = BigInteger.ModPow(pvr, this.x, this.p);
			var sharedSecret = ((BigInt)z).ToBuffer();
			return sharedSecret;
		}

		public void Sign(Buffer data, Buffer signature)
		{
			if (signature.Count != DigestLength)
			{
				throw new ArgumentException("Invalid signature buffer size.");
			}

			// Lock to avoid crash in Mac crypto due to overlapping HMAC calls.
			lock (this.hash)
			{
#if SSH_ENABLE_SPAN
				if (!this.hash.TryComputeHash(data.Span, signature.Span, out _))
				{
					throw new InvalidOperationException("Failed to compute hash.");
				}
#else
				Buffer result = this.hash.ComputeHash(data.Array, data.Offset, data.Count);
#if DEBUG
				Buffer.TrackAllocation(result.Count);
#endif
				result.CopyTo(signature);
#endif
			}
		}

		public void Dispose()
		{
			this.Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposing)
			{
				this.hash.Dispose();
			}
		}
	}
}
