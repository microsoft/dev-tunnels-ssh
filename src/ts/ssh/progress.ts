//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { AuthenticationMessage } from "./messages/authenticationMessages";
import {
	ChannelCloseMessage,
	ChannelFailureMessage,
	ChannelOpenConfirmationMessage,
	ChannelOpenFailureMessage,
	ChannelOpenMessage,
	ChannelSuccessMessage } from "./messages/connectionMessages";
import {
	KeyExchangeDhInitMessage,
	KeyExchangeDhReplyMessage,
	NewKeysMessage } from "./messages/kexMessages";
import { SshMessage } from "./messages/sshMessage";
import {
	ExtensionInfoMessage,
	ServiceAcceptMessage,
	ServiceRequestMessage,
	SessionRequestSuccessMessage } from "./messages/transportMessages";

/**
 * Connection progress
 */
export enum Progress {
	// Client connection to relay
	OpeningClientConnectionToRelay = "OpeningClientConnectionToRelay",
	OpenedClientConnectionToRelay = "OpenedClientConnectionToRelay",

	// Host connection to relay
	OpeningHostConnectionToRelay = "OpeningHostConnectionToRelay",
	OpenedHostConnectionToRelay = "OpenedHostConnectionToRelay",

	// SSH Session Connection
	OpeningSshSessionConnection = "OpeningSshSessionConnection",
	OpenedSshSessionConnection = "OpenedSshSessionConnection",
	SendingProtocolVersionExchange = "SendingProtocolVersionExchange",
	ReceivingProtocolVersionExchange = "ReceivingProtocolVersionExchange",
	StartingKeyExchange = "StartingKeyExchange",
	CompletedKeyExchange = "CompletedKeyExchange",
	SessionEncrypted = "SessionEncrypted",
	StartingSessionAuthentication = "StartingSessionAuthentication",
	CompletedSessionAuthentication = "CompletedSessionAuthentication",
	HostIdentityVerified = "HostIdentityVerified",
	HostIdentityCouldNotBeVerified = "HostIdentityCouldNotBeVerified",
	HostIdentityVerificationFailed = "HostIdentityVerificationFailed",
	HostIdentityVerificationInvalid = "HostIdentityVerificationInvalid",
	SendingKeyExchangeDhInitMessage = "SendingKeyExchangeDhInitMessage",
	ReceivingKeyExchangeDhInitMessage = "ReceivingKeyExchangeDhInitMessage",
	SendingKeyExchangeDhReplyMessage = "SendingKeyExchangeDhReplyMessage",
	ReceivingKeyExchangeDhReplyMessage = "ReceivingKeyExchangeDhReplyMessage",
	SendingNewKeysMessage = "SendingNewKeysMessage",
	ReceivingNewKeysMessage = "ReceivingNewKeysMessage",
	SendingExtensionInfoMessage = "SendingExtensionInfoMessage",
	ReceivingExtensionInfoMessage = "ReceivingExtensionInfoMessage",
	SendingServiceRequestMessage = "SendingServiceRequestMessage",
	ReceivingServiceRequestMessage = "ReceivingServiceRequestMessage",
	SendingAuthenticationRequestMessage = "SendingAuthenticationRequestMessage",
	ReceivingAuthenticationRequestMessage = "ReceivingAuthenticationRequestMessage",
	SendingSessionRequestSuccessMessage = "SendingSessionRequestSuccessMessage",
	ReceivingSessionRequestSuccessMessage = "ReceivingSessionRequestSuccessMessage",
	SendingServiceAcceptMessage = "SendingServiceAcceptMessage",
	ReceivingServiceAcceptMessage = "ReceivingServiceAcceptMessage",

	// Port forwarding messages
	StartingPortForwarding = "StartingPortForwarding",
	CompletedPortForwarding = "CompletedPortForwarding",
	PortForwardingChannelOpened = "PortForwardingChannelOpened",
	SendingPortForwardSuccessMessage = "SendingPortForwardSuccessMessage",
	ReceivingPortForwardSuccessMessage = "ReceivingPortForwardSuccessMessage",
	SendingPortForwardChannelOpenMessage = "SendingPortForwardChannelOpenMessage",
	ReceivingPortForwardChannelOpenMessage = "ReceivingPortForwardChannelOpenMessage",

	// Channel opening messages
	StartingOpenChannel = "StartingOpenChannel",
	CompletedOpenChannel = "CompletedOpenChannel",
	SendingChannelOpenMessage = "SendingChannelOpenMessage",
	ReceivingChannelOpenMessage = "ReceivingChannelOpenMessage",
	SendingChannelCloseMessage = "SendingChannelCloseMessage",
	ReceivingChannelCloseMessage = "ReceivingChannelCloseMessage",
	SendingChannelOpenConfirmationMessage = "SendingChannelOpenConfirmationMessage",
	ReceivingChannelOpenConfirmationMessage = "ReceivingChannelOpenConfirmationMessage",
	SendingChannelOpenFailureMessage = "SendingChannelOpenFailureMessage",
	ReceivingChannelOpenFailureMessage = "ReceivingChannelOpenFailureMessage",
	SendingChannelSuccessMessage = "SendingChannelSuccessMessage",
	ReceivingChannelSuccessMessage = "ReceivingChannelSuccessMessage",
	SendingChannelFailureMessage = "SendingChannelFailureMessage",
	ReceivingChannelFailureMessage = "ReceivingChannelFailureMessage",
}

/**
 * Signature for a function that reports connection progress.
 *
 * @param progress The progress event being reported.
 */
export type ReportProgress = (progress: Progress) => void;

export function reportSendingProgress(message: SshMessage, reportProgress: ReportProgress) {
	if (message instanceof NewKeysMessage) {
		reportProgress(Progress.SendingNewKeysMessage);
	} else if (message instanceof KeyExchangeDhInitMessage) {
		reportProgress(Progress.SendingKeyExchangeDhInitMessage);
	} else if (message instanceof KeyExchangeDhReplyMessage) {
		reportProgress(Progress.SendingKeyExchangeDhReplyMessage);
	} else if (message instanceof AuthenticationMessage) {
		reportProgress(Progress.SendingAuthenticationRequestMessage);
	} else if (message instanceof ServiceRequestMessage) {
		reportProgress(Progress.SendingServiceRequestMessage);
	} else if (message instanceof ServiceAcceptMessage) {
		reportProgress(Progress.SendingServiceAcceptMessage);
	} else if (message instanceof SessionRequestSuccessMessage) {
		reportProgress(Progress.SendingSessionRequestSuccessMessage);
	} else if (message instanceof ExtensionInfoMessage) {
		reportProgress(Progress.SendingExtensionInfoMessage);
	}  else if (message instanceof ChannelOpenMessage) {
		reportProgress(Progress.SendingChannelOpenMessage);
	} else if (message instanceof ChannelCloseMessage) {
		reportProgress(Progress.SendingChannelCloseMessage);
	} else if (message instanceof ChannelOpenConfirmationMessage) {
		reportProgress(Progress.SendingChannelOpenConfirmationMessage);
	} else if (message instanceof ChannelOpenFailureMessage) {
		reportProgress(Progress.SendingChannelFailureMessage);
	} else if (message instanceof ChannelSuccessMessage) {
		reportProgress(Progress.SendingChannelSuccessMessage);
	} else if (message instanceof ChannelFailureMessage) {
		reportProgress(Progress.SendingChannelFailureMessage);
	}
}

export function reportReceivingProgress(message: SshMessage, reportProgress: ReportProgress) {
	if (message instanceof NewKeysMessage) {
		reportProgress(Progress.ReceivingNewKeysMessage);
	} else if (message instanceof KeyExchangeDhInitMessage) {
		reportProgress(Progress.ReceivingKeyExchangeDhInitMessage);
	} else if (message instanceof KeyExchangeDhReplyMessage) {
		reportProgress(Progress.ReceivingKeyExchangeDhReplyMessage);
	}  else if (message instanceof AuthenticationMessage) {
		reportProgress(Progress.ReceivingAuthenticationRequestMessage);
	} else if (message instanceof ServiceRequestMessage) {
		reportProgress(Progress.ReceivingServiceRequestMessage);
	} else if (message instanceof ServiceAcceptMessage) {
		reportProgress(Progress.ReceivingServiceAcceptMessage);
	} else if (message instanceof SessionRequestSuccessMessage) {
		reportProgress(Progress.ReceivingSessionRequestSuccessMessage);
	} else if (message instanceof ExtensionInfoMessage) {
		reportProgress(Progress.ReceivingExtensionInfoMessage);
	}  else if (message instanceof ChannelOpenMessage) {
		reportProgress(Progress.ReceivingChannelOpenMessage);
	} else if (message instanceof ChannelCloseMessage) {
		reportProgress(Progress.ReceivingChannelCloseMessage);
	} else if (message instanceof ChannelOpenConfirmationMessage) {
		reportProgress(Progress.ReceivingChannelOpenConfirmationMessage);
	} else if (message instanceof ChannelOpenFailureMessage) {
		reportProgress(Progress.ReceivingChannelOpenFailureMessage);
	} else if (message instanceof ChannelSuccessMessage) {
		reportProgress(Progress.ReceivingChannelSuccessMessage);
	} else if (message instanceof ChannelFailureMessage) {
		reportProgress(Progress.ReceivingChannelFailureMessage);
	}
}
