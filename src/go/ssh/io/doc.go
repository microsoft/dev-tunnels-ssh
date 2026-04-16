// Copyright (c) Microsoft Corporation. All rights reserved.

// Package sshio provides binary data readers and writers for the SSH wire protocol.
//
// [SSHDataReader] and [SSHDataWriter] implement the SSH binary encoding defined
// in RFC 4251 section 5, supporting types such as byte, boolean, uint32, uint64,
// string, mpint (arbitrary-precision integer), and name-list.
//
// This package also provides [BigIntToSSHBytes] and [SSHBytesToBigInt] for
// converting between Go's [math/big.Int] and SSH's mpint wire format.
package sshio
