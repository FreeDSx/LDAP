# AppVeyor script to install AD (Step 2)
#   This part runs after the reboot to finish up a few tasks.

Set-PSDebug -Trace 1

Import-Module ServerManager

# Installs the EntCA role, which on a DC automagically allows LDAPS / StartTLS
Install-WindowsFeature Adcs-Cert-Authority
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -Force

# Enable the recycle bin, can use this for control tests
Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target 'example.com' -Server $env:COMPUTERNAME

Install-WindowsFeature -IncludeManagementTools RSAT-ADDS-Tools
ldifde -i -k -f "C:\projects\freedsx-ldap\tests\resources\activedirectory\data.ldif"

New-ADUser `
    -Name "admin" `
    -AccountPassword (ConvertTo-SecureString "P@ssword12345" -AsPlainText -Force) `
    -DisplayName "admin" `
    -EmailAddress "admin@example.com" `
    -Enabled $True `
    -GivenName "Admin" `
    -Path "DC=example,DC=com" `
    -SamAccountName "admin" `
    -UserPrincipalName "admin@example.com"
