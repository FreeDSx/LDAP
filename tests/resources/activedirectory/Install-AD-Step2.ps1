# AppVeyor script to install AD (Step 2)
#   This part runs after the reboot to finish up a few tasks.

Set-PSDebug -Trace 1

Import-Module ServerManager

Add-Content -Encoding ASCII "C:\Windows\System32\drivers\etc\hosts" "`r`n127.0.0.1 foo.com"
Add-Content -Encoding ASCII "C:\Windows\System32\drivers\etc\hosts" "`r`n127.0.0.1 example.com"

php "C:\projects\freedsx-ldap\tests\resources\activedirectory\generate-ldif.php"

ldifde -h -i -f "C:\projects\freedsx-ldap\tests\resources\activedirectory\ldif\data.ldif"
ldifde -h -i -f "C:\projects\freedsx-ldap\tests\resources\activedirectory\ldif\admin.ldif"
ldifde -h -i -f "C:\projects\freedsx-ldap\tests\resources\activedirectory\ldif\data-group.ldif"

$Password = ConvertTo-SecureString -String "P@ssword12345" -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ('admin@example.com', $Password)

# Enable the recycle bin, can use this for control tests
Enable-ADOptionalFeature `
    -Identity 'Recycle Bin Feature' `
    -Scope ForestOrConfigurationSet `
    -Target 'example.com' `
    -Server $env:COMPUTERNAME `
    -Confirm:$False `
    -Credential $Credential

New-Item -Path "C:\projects\freedsx-ldap\tests\resources" -Name "cert" -ItemType directory

openssl.exe genrsa -out "C:\projects\freedsx-ldap\tests\resources\cert\ca.key" 2048
openssl.exe req -new -x509 -sha256 -days 3650 -key "C:\projects\freedsx-ldap\tests\resources\cert\ca.key" -out "C:\projects\freedsx-ldap\tests\resources\cert\ca.crt" -subj "/C=US/ST=WI/L=Madison/O=FreeDSx/OU=DS/CN=example"
Import-Certificate -Filepath "C:\projects\freedsx-ldap\tests\resources\cert\ca.crt" -CertStoreLocation cert:\LocalMachine\Root

certreq.exe -new "C:\projects\freedsx-ldap\tests\resources\activedirectory\cert\cert.inf" "C:\projects\freedsx-ldap\tests\resources\activedirectory\cert\cert.csr"
openssl.exe x509 -req -sha256 -days 3650 -in "C:\projects\freedsx-ldap\tests\resources\activedirectory\cert\cert.csr" -CA "C:\projects\freedsx-ldap\tests\resources\cert\ca.crt" -CAkey "C:\projects\freedsx-ldap\tests\resources\cert\ca.key" -extfile "C:\projects\freedsx-ldap\tests\resources\activedirectory\cert\ext.txt" -CAcreateserial -out "C:\projects\freedsx-ldap\tests\resources\activedirectory\cert\ldap.crt"
certreq.exe -accept "C:\projects\freedsx-ldap\tests\resources\activedirectory\cert\ldap.crt"

Start-Process `
    -FilePath "ldifde.exe" `
    -ArgumentList '-i -f "C:\projects\freedsx-ldap\tests\resources\activedirectory\ldif\tls.ldif"' `
    -Wait `
    -Credential $Credential
