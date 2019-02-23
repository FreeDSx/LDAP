# AppVeyor script to install AD (Step 2)
#   This part runs after the reboot to finish up a few tasks.

Set-PSDebug -Trace 1

Import-Module ServerManager

Add-Content C:\Windows\System32\drivers\etc\hosts "`r`n127.0.0.1 foo.com"

Install-WindowsFeature -IncludeManagementTools Adcs-Cert-Authority

ldifde -i -k -f "C:\projects\freedsx-ldap\tests\resources\activedirectory\ldif\data.ldif"
ldifde -h -i -k -f "C:\projects\freedsx-ldap\tests\resources\activedirectory\ldif\admin.ldif"

$Password = ConvertTo-SecureString -String "P@ssword12345" -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ('admin@example.com', $Password)

# Installs the EntCA role, which on a DC automagically allows LDAPS / StartTLS
Install-AdcsCertificationAuthority `
    -CAType EnterpriseRootCa `
    -Confirm:$False `
    -Credential $Credential `
    -Force

# Enable the recycle bin, can use this for control tests
Enable-ADOptionalFeature `
    -Identity 'Recycle Bin Feature' `
    -Scope ForestOrConfigurationSet `
    -Target 'example.com' `
    -Server $env:COMPUTERNAME `
    -Confirm:$False `
    -Credential $Credential

New-Item -Path "C:\projects\freedsx-ldap\tests\resources" -Name "cert" -ItemType directory
Get-ChildItem cert:\LocalMachine\Root | `
    Where-Object { $_.Subject -match $env:COMPUTERNAME } | `
    Select-Object -First 1 | `
    Export-Certificate -FilePath "C:\projects\freedsx-ldap\tests\resources\cert\ca.crt"
