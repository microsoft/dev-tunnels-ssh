//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import {
	SshAlgorithms,
	SshDataWriter,
	SshDataReader,
	ChannelOpenMessage,
} from '@microsoft/dev-tunnels-ssh';
import { Benchmark } from './benchmark';

declare type hrtime = [number, number];
const millis = ([s, ns]: hrtime) => s * 1000 + ns / 1000000;

export class ChannelDataSerializationBenchmark extends Benchmark {
	private static readonly RoundTripTimeMeasurement = 'Round-trip time (ms)';

	public constructor() {
		super(
			'Serialize ChannelData',
			'protocol-serialization',
			{ msg: 'channel-data' },
		);

		this.higherIsBetter.set(
			ChannelDataSerializationBenchmark.RoundTripTimeMeasurement,
			false,
		);
	}

	public async run(): Promise<void> {
		const iterations = 1000;
		const data = Buffer.alloc(32768);
		SshAlgorithms.random.getBytes(data);

		const startTime: hrtime = process.hrtime();

		for (let i = 0; i < iterations; i++) {
			// Serialize: type(94) + recipientChannel(uint32) + data(binary)
			const writer = new SshDataWriter(Buffer.alloc(32768 + 16));
			writer.writeByte(94); // SSH_MSG_CHANNEL_DATA
			writer.writeUInt32(1); // recipientChannel
			writer.writeBinary(data);
			const buffer = writer.toBuffer();

			// Deserialize
			const reader = new SshDataReader(buffer);
			reader.readByte(); // type
			reader.readUInt32(); // recipientChannel
			reader.readBinary(); // data
		}

		const elapsed: hrtime = process.hrtime(startTime);

		this.addMeasurement(
			ChannelDataSerializationBenchmark.RoundTripTimeMeasurement,
			millis(elapsed) / iterations,
		);
	}

	public async dispose(): Promise<void> {}
}

export class ChannelOpenSerializationBenchmark extends Benchmark {
	private static readonly RoundTripTimeMeasurement = 'Round-trip time (ms)';

	public constructor() {
		super(
			'Serialize ChannelOpen',
			'protocol-serialization',
			{ msg: 'channel-open' },
		);

		this.higherIsBetter.set(
			ChannelOpenSerializationBenchmark.RoundTripTimeMeasurement,
			false,
		);
	}

	public async run(): Promise<void> {
		const iterations = 1000;
		const msg = new ChannelOpenMessage();
		msg.channelType = 'session';
		msg.senderChannel = 0;
		msg.maxWindowSize = 1024 * 1024;
		msg.maxPacketSize = 32 * 1024;

		const startTime: hrtime = process.hrtime();

		for (let i = 0; i < iterations; i++) {
			const buffer = msg.toBuffer();
			const reader = new SshDataReader(buffer);
			const msg2 = new ChannelOpenMessage();
			msg2.read(reader);
		}

		const elapsed: hrtime = process.hrtime(startTime);

		this.addMeasurement(
			ChannelOpenSerializationBenchmark.RoundTripTimeMeasurement,
			millis(elapsed) / iterations,
		);
	}

	public async dispose(): Promise<void> {}
}

// Realistic algorithm lists matching SSH defaults
const kexAlgorithms = [
	'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
	'diffie-hellman-group14-sha256', 'diffie-hellman-group16-sha512',
];
const hostKeyAlgorithms = [
	'rsa-sha2-256', 'rsa-sha2-512', 'ecdsa-sha2-nistp256',
	'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
];
const encryptionAlgorithms = [
	'aes256-gcm@openssh.com', 'aes256-cbc', 'aes256-ctr',
];
const macAlgorithms = [
	'hmac-sha2-256', 'hmac-sha2-512',
	'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com',
];
const compressionAlgorithms = ['none'];

function serializeKexInit(writer: SshDataWriter): void {
	writer.writeByte(20); // SSH_MSG_KEXINIT
	writer.writeRandom(16); // cookie
	writer.writeList(kexAlgorithms, 'ascii');
	writer.writeList(hostKeyAlgorithms, 'ascii');
	writer.writeList(encryptionAlgorithms, 'ascii'); // client-to-server
	writer.writeList(encryptionAlgorithms, 'ascii'); // server-to-client
	writer.writeList(macAlgorithms, 'ascii'); // client-to-server
	writer.writeList(macAlgorithms, 'ascii'); // server-to-client
	writer.writeList(compressionAlgorithms, 'ascii'); // client-to-server
	writer.writeList(compressionAlgorithms, 'ascii'); // server-to-client
	writer.writeList([], 'ascii'); // languages client-to-server
	writer.writeList([], 'ascii'); // languages server-to-client
	writer.writeBoolean(false); // first_kex_packet_follows
	writer.writeUInt32(0); // reserved
}

function deserializeKexInit(reader: SshDataReader): void {
	reader.readByte(); // type
	reader.read(16); // cookie
	reader.readList('ascii'); // kex algorithms
	reader.readList('ascii'); // host key algorithms
	reader.readList('ascii'); // encryption client-to-server
	reader.readList('ascii'); // encryption server-to-client
	reader.readList('ascii'); // mac client-to-server
	reader.readList('ascii'); // mac server-to-client
	reader.readList('ascii'); // compression client-to-server
	reader.readList('ascii'); // compression server-to-client
	reader.readList('ascii'); // languages client-to-server
	reader.readList('ascii'); // languages server-to-client
	reader.readBoolean(); // first_kex_packet_follows
	reader.readUInt32(); // reserved
}

export class KeyExchangeInitSerializationBenchmark extends Benchmark {
	private static readonly RoundTripTimeMeasurement = 'Round-trip time (ms)';

	public constructor() {
		super(
			'Serialize KeyExchangeInit',
			'protocol-serialization',
			{ msg: 'kex-init' },
		);

		this.higherIsBetter.set(
			KeyExchangeInitSerializationBenchmark.RoundTripTimeMeasurement,
			false,
		);
	}

	public async run(): Promise<void> {
		const iterations = 1000;

		const startTime: hrtime = process.hrtime();

		for (let i = 0; i < iterations; i++) {
			// Serialize
			const writer = new SshDataWriter(Buffer.alloc(512));
			serializeKexInit(writer);
			const buffer = writer.toBuffer();

			// Deserialize
			const reader = new SshDataReader(buffer);
			deserializeKexInit(reader);
		}

		const elapsed: hrtime = process.hrtime(startTime);

		this.addMeasurement(
			KeyExchangeInitSerializationBenchmark.RoundTripTimeMeasurement,
			millis(elapsed) / iterations,
		);
	}

	public async dispose(): Promise<void> {}
}

export class KexCycleBenchmark extends Benchmark {
	private static readonly KexCycleTimeMeasurement = 'KEX cycle time (ms)';

	public constructor() {
		super(
			'KEX Cycle ECDH P-384',
			'protocol-kex-cycle',
			{ algo: 'ecdh-sha2-nistp384' },
		);

		this.higherIsBetter.set(KexCycleBenchmark.KexCycleTimeMeasurement, false);
	}

	public async run(): Promise<void> {
		const kexAlgorithm = SshAlgorithms.keyExchange.ecdhNistp384Sha384!;
		const hostKeyAlgorithm = SshAlgorithms.publicKey.ecdsaSha2Nistp384!;

		// Pre-generate server host key (outside timed section)
		const hostKeyPair = await hostKeyAlgorithm.generateKeyPair(384);
		const hostKeyBytes = await hostKeyPair.getPublicKeyBytes();

		const startTime: hrtime = process.hrtime();

		// 1. Both sides serialize KEXINIT
		const clientKexInitWriter = new SshDataWriter(Buffer.alloc(512));
		serializeKexInit(clientKexInitWriter);
		const serverKexInitWriter = new SshDataWriter(Buffer.alloc(512));
		serializeKexInit(serverKexInitWriter);

		// 2. Client starts key exchange
		const clientKex = kexAlgorithm.createKeyExchange();
		const clientPublic = await clientKex.startKeyExchange();

		// 3. Serialize client's DH_INIT (E value)
		const dhInitWriter = new SshDataWriter(Buffer.alloc(256));
		dhInitWriter.writeByte(30); // SSH_MSG_KEXDH_INIT
		dhInitWriter.writeBinary(clientPublic);
		const dhInitBuffer = dhInitWriter.toBuffer();

		// 4. Server receives DH_INIT, deserializes E
		const dhInitReader = new SshDataReader(dhInitBuffer);
		dhInitReader.readByte(); // type
		const clientE = dhInitReader.readBinary();

		// 5. Server does key exchange
		const serverKex = kexAlgorithm.createKeyExchange();
		const serverPublic = await serverKex.startKeyExchange();
		await serverKex.decryptKeyExchange(clientE);

		// 6. Server signs exchange hash and serializes DH_REPLY
		const testData = Buffer.alloc(48);
		SshAlgorithms.random.getBytes(testData);
		const signer = hostKeyAlgorithm.createSigner(hostKeyPair);
		const signature = await signer.sign(testData);

		const dhReplyWriter = new SshDataWriter(Buffer.alloc(512));
		dhReplyWriter.writeByte(31); // SSH_MSG_KEXDH_REPLY
		dhReplyWriter.writeBinary(hostKeyBytes!);
		dhReplyWriter.writeBinary(serverPublic);
		dhReplyWriter.writeBinary(signature);
		const dhReplyBuffer = dhReplyWriter.toBuffer();

		// 7. Client receives DH_REPLY, deserializes
		const dhReplyReader = new SshDataReader(dhReplyBuffer);
		dhReplyReader.readByte(); // type
		dhReplyReader.readBinary(); // hostKey
		const serverF = dhReplyReader.readBinary();
		const sig = dhReplyReader.readBinary();

		// 8. Client completes key exchange
		await clientKex.decryptKeyExchange(serverF);

		// 9. Client verifies signature
		const verifier = hostKeyAlgorithm.createVerifier(hostKeyPair);
		await verifier.verify(testData, sig);

		const elapsed: hrtime = process.hrtime(startTime);

		this.addMeasurement(KexCycleBenchmark.KexCycleTimeMeasurement, millis(elapsed));

		signer.dispose();
		verifier.dispose();
		clientKex.dispose();
		serverKex.dispose();
		hostKeyPair.dispose();
	}

	public async dispose(): Promise<void> {}
}
