# AppVeyor script to install AD (Step 2)
#   This part runs after the reboot to finish up a few tasks.

Set-PSDebug -Trace 1

Import-Module ServerManager

Add-Content C:\Windows\System32\drivers\etc\hosts "`nfoo.com 127.0.0.1"

# Installs the EntCA role, which on a DC automagically allows LDAPS / StartTLS
Install-AdcsCertificationAuthority `
    -CAType EnterpriseRootCa `
    -Confirm:$False `
    -Force

# Enable the recycle bin, can use this for control tests
Enable-ADOptionalFeature `
    -Identity 'Recycle Bin Feature' `
    -Scope ForestOrConfigurationSet `
    -Target 'example.com' `
    -Server $env:COMPUTERNAME `
    -Confirm:$False

ldifde -i -k -f "C:\projects\freedsx-ldap\tests\resources\activedirectory\data.ldif"

# This is to mimic the OpenLDAP CI build admin user.
$AdminUser = New-ADUser `
    -Name "admin" `
    -AccountPassword (ConvertTo-SecureString "P@ssword12345" -AsPlainText -Force) `
    -DisplayName "admin" `
    -EmailAddress "admin@example.com" `
    -Enabled $True `
    -GivenName "Admin" `
    -Path "DC=example,DC=com" `
    -SamAccountName "admin" `
    -UserPrincipalName "admin@example.com" `
    -ErrorAction Stop
Add-ADGroupMember -Identity "Domain Admins" -Members "admin@example.com"
Add-ADGroupMember -Identity "Enterprise Admins" -Members $Env:COMPUTERNAME
