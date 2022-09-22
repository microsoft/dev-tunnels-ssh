//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

export class SshChannelClosedEventArgs {
	public constructor();
	public constructor(exitStatus: number);
	public constructor(exitSignal: string, errorMessage?: string);
	public constructor(error: Error);
	public constructor(exitStatusOrSignalOrError?: number | string | Error, errorMessage?: string) {
		if (typeof exitStatusOrSignalOrError === 'number') {
			this.exitStatus = exitStatusOrSignalOrError;
		} else if (typeof exitStatusOrSignalOrError === 'string') {
			this.exitSignal = exitStatusOrSignalOrError;
			this.errorMessage = errorMessage;
		} else if (exitStatusOrSignalOrError instanceof Error) {
			this.error = exitStatusOrSignalOrError;
		}
	}

	public readonly exitStatus?: number;
	public readonly exitSignal?: string;
	public readonly errorMessage?: string;
	public readonly error?: Error;
}
