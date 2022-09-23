<#

SSH Test Keys

Key files in this directory are representations of a _single_ RSA public/private key pair
("testkey") that was generated once with OpenSSH `ssh-keygen` and converted/exported into various
formats, using `ssh-keygen` again to do the conversion. Private key files ending with `-pw` are
password-protected; their password is "password".

These keys are used only for SSH library testing and must not be used to actually secure anything.

This script was used to generate the keys. Note this requires a very recent version of OpenSSH
`ssh-keygen`, as older versions do not support the newer OpenSSH private key format.

The `puttygen.exe` tool on Windows can also be used to manually convert between some of the key
formats, including the 'SSH2' format which `ssh-keygen` does not support.
#>

$k = "testkey"
$c = "comment"
$p = "password"

$alg = "rsa4096"
#$alg = "ecdsa384"

# Tests expect newlines to be consistent, matching the current OS defaults.
# (Git will automatically convert newlines when committing.)
function Convert-NewLines($File) {
	(Get-Content $File) | Set-Content $File
}

# ssh-keygen refuses to read a private key file unless ACLs are restricted.
function Set-PrivateAcl($File) {
	$acl = Get-Acl $File
	$acl.SetAccessRuleProtection($true, $false) # Disable inheritance
	$acl.SetAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
		[System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
		[System.Security.AccessControl.FileSystemRights]::FullControl,
		[System.Security.AccessControl.AccessControlType]::Allow))
	$acl | Set-Acl $File
}

# Restores default ACLs on a file.
function Set-DefaultAcl($File) {
	Copy-Item $File "$File.tmp"
	Remove-Item $File
	Move-Item "$File.tmp" $File
}

# Creates new private and public key files in OpenSSH format.
function New-KeyPair($KeyAlgorithm, $PrivateKeyFile, $PublicKeyFile, $Comment) {
	if ($KeyAlgorithm -match "^ecdsa\d+") {
		$keyType = "ecdsa"
		$keySize = $KeyAlgorithm.Substring(5)
	}
	elseif ($KeyAlgorithm -match "^rsa\d+") {
		$keyType = "rsa"
		$keySize = $KeyAlgorithm.Substring(3)
	}
	else {
		throw "Unsupported key algorithm" + $KeyAlgorithm
	}

	Remove-Item $PrivateKeyFile -ErrorAction SilentlyContinue
	ssh-keygen -q -f $PrivateKeyFile -t $keyType -b $keySize -C $Comment -P '""' > $null
	Set-DefaultAcl $PrivateKeyFile
	Convert-NewLines $PrivateKeyFile

	Remove-Item $PublicKeyFile -ErrorAction SilentlyContinue
	Move-Item "$PrivateKeyFile.pub" $PublicKeyFile
	Convert-NewLines $PublicKeyFile
}

# Converts a private key file to a different format using ssh-keygen.
function Convert-PrivateKey($SourceFile, $TargetFile, $Format, $Password) {
	Copy-Item $SourceFile $TargetFile
	Set-PrivateAcl $TargetFile
	if ($Format -ne "openssh" -and $Password) {
		ssh-keygen -f $TargetFile -p -N "$Password" -m "$Format" > $null
	} elseif ($Format -ne "openssh") {
		ssh-keygen -f $TargetFile -p -N '""' -m "$Format" > $null
	} elseif ($Password) {
		ssh-keygen -f $TargetFile -p -N "$Password" > $null
	}
	Set-DefaultAcl $TargetFile
	Convert-NewLines $TargetFile
}

function Convert-PublicKey($PrivateKeyFile, $PublicKeyFile, $Format, $Comment) {
	ssh-keygen -q -f $PrivateKeyFile -e -m "$Format" > $PublicKeyFile

	if ($Comment) {
		(Get-Content $PublicKeyFile |
			ForEach-Object { $_ -replace "Comment: .*", "Comment: `"$Comment`"" }) |
			Set-Content $PublicKeyFile
	}
}

$privateKeyFile = "$k-private-$alg-openssh.txt"
$publicKeyFile = "$k-public-$alg-ssh.txt"

New-KeyPair $alg $privateKeyFile $publicKeyFile -Comment $c
Convert-PrivateKey $privateKeyFile "$k-private-$alg-openssh-pw.txt" -Format "openssh" -Password $p

Convert-PrivateKey $privateKeyFile "$k-private-$alg-pkcs8.txt" -Format "pkcs8"
Convert-PrivateKey $privateKeyFile "$k-private-$alg-pkcs8-pw.txt" -Format "pkcs8" -Password $p
Convert-PublicKey $publicKeyFile "$k-public-$alg-pkcs8.txt" -Format "pkcs8"

if ($alg -match "^rsa\d+") {
	Convert-PrivateKey $privateKeyFile "$k-private-$alg-pkcs1.txt" -Format "pem"
	Convert-PrivateKey $privateKeyFile "$k-private-$alg-pkcs1-pw.txt" -Format "pem" -Password $p

	Convert-PublicKey $publicKeyFile "$k-public-$alg-pkcs1.txt" -Format "pem"

	Convert-PublicKey $publicKeyFile "$k-public-$alg-ssh2.txt" -Format "rfc4716" -Comment $c
}
elseif ($alg -match "^ecdsa\d+") {
	Convert-PrivateKey $privateKeyFile "$k-private-$alg-sec1.txt" -Format "sec1"
}
