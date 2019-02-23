# AppVeyor script to install AD (Step 1)
#   Installs the needed AD role as the first step. A reboot is then needed.

Set-PSDebug -Trace 1

Install-WindowsFeature AD-Domain-Services

Import-Module ADDSDeployment
Install-ADDSForest -CreateDnsDelegation:$false `
    -DatabasePath “C:\Windows\NTDS” `
    -DomainMode “WinThreshold” `
    -DomainName “example.com” `
    -DomainNetbiosName “EXAMPLE” `
    -ForestMode “WinThreshold” `
    -InstallDns:$true `
    -LogPath “C:\Windows\NTDS” `
    -NoRebootOnCompletion:$true `
    -SysvolPath “C:\Windows\SYSVOL” `
    -Force:$true
