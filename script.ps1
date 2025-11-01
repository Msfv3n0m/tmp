Install-WindowsFeature -Name Windows-Defender-Features
Start-Service -Name WinDefend
Update-MpSignature
# Enable UAC, Firewall, and Defender - Undo registry and service disables

# Enable UAC
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1

# Enable Defender Service
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\SecurityHealthService' -Name Start -Value 2

# Enable Defender Anti-Spyware
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 0

# Enable Defender Anti-Virus
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender' -Name DisableAntiVirus -Value 0

# Enable Defender MpEngine PUS
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine' -Name MpEnablePus -Value 1

# Enable Defender Real-Time Protection Features
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableBehaviorMonitoring -Value 0
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableIOAVProtection -Value 0
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableOnAccessProtection -Value 0
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableRealtimeMonitoring -Value 0
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableScanOnRealtimeEnable -Value 0
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableScriptScanning -Value 0

# Enable Defender Enhanced Notifications
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting' -Name DisableEnhancedNotifications -Value 0

# Enable Defender Block at First Seen
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet' -Name DisableBlockAtFirstSeen -Value 0

# Enable Defender Spynet Reporting
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet' -Name SpynetReporting -Value 1

# Enable Defender Samples Consent (Set to recommended value, e.g. 1)
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet' -Name SubmitSamplesConsent -Value 1

# Restore Windows Defender Scheduled Tasks (remove empty string entries if present)
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'Windows Defender' -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'Windows Defender Scheduled Scan' -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'Windows Defender Verification' -ErrorAction SilentlyContinue

# Start Windows Update Service and set to auto
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# Enable Windows Update
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 0

# Disable Remote UAC (set back to 0)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Value 0

# Restore Windows Defender Firewall (all profiles)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Remove custom ICMP allow rules (if present)
Get-NetFirewallRule -DisplayName 'ICMP Allow incoming V4 echo request' | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName 'ICMP Allow incoming V6 echo request' | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# Remove custom Network Discovery rule (if present)
Get-NetFirewallRule -DisplayName '@FirewallAPI.dll,-32752' | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# Enable Windows Defender Firewall (all profiles)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Note: Some registry settings may not take effect until after a reboot or service restart.
