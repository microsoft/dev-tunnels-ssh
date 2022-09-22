//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshServiceConstructor } from './sshService';

/**
 * Decorator applied to suclasses of `SshService` that declares how the service gets activated.
 */
export function serviceActivation(activation: ServiceActivation) {
	return (constructor: Function) => {
		if (!(<any>constructor).activations) {
			(<any>constructor).activations = [];
		}
		(<any>constructor).activations.push(activation);
	};
}

/**
 * Rules for how a service gets activated for an SSH session.
 */
export interface ServiceActivation {
	/**
	 * Activate the service when a service request is received for the specified name.
	 *
	 * Only server-side services can be activated using a service request from the client.
	 * (Other activation methods can work in either direction.)
	 */
	readonly serviceRequest?: string;

	/**
	 * Activate the service when a session request is received for the specified request type.
	 */
	readonly sessionRequest?: string;

	/**
	 * Activate the service when a request is received to open a channel of the specified
	 * channel type.
	 */
	readonly channelType?: string;

	/**
	 * Activate the service when a channel request is received for the specified channel
	 * request type.
	 *
	 * If both `channelType` and `channelRequest` are set, then the service is activated only
	 * when the specified request is received on the specified channel type.
	 */
	readonly channelRequest?: string;
}

/**
 * Locates a service type in configuration, using a predicate to check service activation
 * attributes.
 *
 * @param serviceConfigs Service configuration dictionary from `SshSessionConfiguration.services`.
 * @param predicate Function to test whether a service activation attribute matches some condition.
 * @returns Service type (constructor), or null if no service type satisfies the predicate.
 */
export function findService(
	serviceConfigs: Map<SshServiceConstructor, any>,
	predicate: (activation: ServiceActivation) => boolean,
): SshServiceConstructor | null {
	for (let serviceType of serviceConfigs.keys()) {
		const activations: ServiceActivation[] = (<any>serviceType).activations;

		let foundActivation = false;
		for (let activation of activations) {
			foundActivation = true;
			if (predicate(activation)) {
				return serviceType;
			}
		}

		if (!foundActivation) {
			throw new Error(
				`SSH service type '${serviceType.name}' must have one or more ` +
					`'serviceActivation' decorators.`,
			);
		}
	}

	return null;
}
