//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Progress } from '../progress';

export class SshReportProgressEventArgs {
	public constructor(
		public readonly progress: Progress,
		public readonly sessionNumber?: number
	) {}

	public toString() {
		return `Progress: ${this.progress}` +
			this.sessionNumber ? ` Session number: ${this.sessionNumber}` : '';
	}
}
