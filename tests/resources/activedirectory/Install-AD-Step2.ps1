# AppVeyor script to install AD (Step 2)
#   This part runs after the reboot to finish up a few tasks.

Import-Module ServerManager

# Installs the EntCA role, which automagically allows LDAPS / StartTLS
Add-WindowsFeature Adcs-Cert-Authority
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -Force

# Enable the recycle bin, can use this for control tests
Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target 'example.com' -Server $env:COMPUTERNAME
