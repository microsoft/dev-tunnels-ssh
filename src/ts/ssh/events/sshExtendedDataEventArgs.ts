//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

export enum SshExtendedDataType {
	/**
	 * The extended data type SSH_EXTENDED_DATA_STDERR has been defined for stderr data.
	 */
	STDERR = 1,
}

export class SshExtendedDataEventArgs {
	public constructor(
		public readonly dataTypeCode: SshExtendedDataType,
		public readonly data: Buffer,
	) {}

	public toString() {
		return `${SshExtendedDataType[this.dataTypeCode]}: ${this.data.toString()}`;
	}
}
