# AppVeyor script to install AD (Step 1)
#   Installs the needed AD role as the first step. A reboot is then needed.

Set-PSDebug -Trace 1

Install-WindowsFeature -IncludeManagementTools AD-Domain-Services, RSAT-ADDS-Tools

Import-Module ADDSDeployment
Install-ADDSForest -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -DomainMode "Default" `
    -DomainName "example.com" `
    -DomainNetbiosName "EXAMPLE" `
    -ForestMode "Default" `
    -InstallDns:$true `
    -LogPath "C:\Windows\NTDS" `
    -NoRebootOnCompletion:$true `
    -SysvolPath "C:\Windows\SYSVOL" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssword12345" -AsPlainText -Force) `
    -Force:$true
