// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"fmt"
	"strings"
	"unicode"
)

// Version of the Go SSH library.
const (
	libraryName    = "dev-tunnels-ssh-go"
	libraryVersion = "0.1"
)

// VersionInfo contains parsed SSH version information from the version string
// exchanged during the initial SSH handshake.
type VersionInfo struct {
	versionString   string
	ProtocolVersion string
	Name            string
	Version         string
}

// Parse attempts to parse an SSH version string (e.g., "SSH-2.0-OpenSSH_7.9")
// into a VersionInfo. Returns nil if the string cannot be parsed.
func ParseVersionInfo(versionString string) *VersionInfo {
	parts := strings.SplitN(versionString, "-", 3)
	if len(parts) != 3 || parts[0] != "SSH" {
		return nil
	}

	protocolVersion := parts[1]
	// Validate protocol version contains digits and dots only.
	for _, c := range protocolVersion {
		if !unicode.IsDigit(c) && c != '.' {
			return nil
		}
	}

	nameAndVersion := parts[2]

	// Find last underscore before any space (space separates optional comments).
	spaceIndex := strings.IndexByte(nameAndVersion, ' ')
	searchEnd := len(nameAndVersion) - 1
	if spaceIndex >= 0 {
		searchEnd = spaceIndex
	}

	lastUnderscore := strings.LastIndex(nameAndVersion[:searchEnd+1], "_")

	var name, version string
	if lastUnderscore >= 0 {
		name = strings.ReplaceAll(nameAndVersion[:lastUnderscore], "_", " ")

		// Extract version: take characters from after underscore until non-digit, non-dot.
		versionStr := nameAndVersion[lastUnderscore+1:]
		for i, c := range versionStr {
			if !unicode.IsDigit(c) && c != '.' {
				versionStr = versionStr[:i]
				break
			}
		}
		version = versionStr
	} else {
		name = nameAndVersion
		version = ""
	}

	return &VersionInfo{
		versionString:   versionString,
		ProtocolVersion: protocolVersion,
		Name:            name,
		Version:         version,
	}
}

// GetLocalVersion returns the version info for this SSH library.
func GetLocalVersion() *VersionInfo {
	versionString := fmt.Sprintf("SSH-2.0-%s_%s", libraryName, libraryVersion)
	return &VersionInfo{
		versionString:   versionString,
		ProtocolVersion: "2.0",
		Name:            libraryName,
		Version:         libraryVersion,
	}
}

// String returns the original SSH version string.
func (v *VersionInfo) String() string {
	return v.versionString
}

// IsDevTunnelsSSH returns true if this version info represents some version
// of the Dev Tunnels SSH library (C#, TypeScript, or Go).
func (v *VersionInfo) IsDevTunnelsSSH() bool {
	return v.Name == "Microsoft.VisualStudio.Ssh" ||
		v.Name == "Microsoft.DevTunnels.Ssh" ||
		v.Name == "vs-ssh" ||
		v.Name == "dev-tunnels-ssh" ||
		v.Name == libraryName
}
