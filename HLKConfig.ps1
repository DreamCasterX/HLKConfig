﻿
$creator = "Mike Lu (klu7@lenovo.com)"
$change_date = "2/14/2025"
$version = "1.0"

# [Note] 
# Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned` first if the script is restriced

# User-defined settings
$NIC_interface="Ethernet0"  # For NB: Ethernet    For Server: Ethernet0


do {
    Clear-Host
	Write-Host "[HLK Auto Configuration Tool]"
	Write-Host ""
	Write-Host "Select a configuration option"
	Write-Host "(s) SUT   (t) TC   (u) Uninstall HLK from SUT  (q) Quit "
	$choice = Read-Host "ans"
    $choice = $choice.ToLower()
    switch ($choice) {
        "t" {
            Write-Host "Now configuring HLK TC..."
            # Set sleep & display off to Never
			powercfg /change standby-timeout-ac 0
			powercfg /change standby-timeout-dc 0
			powercfg /change monitor-timeout-ac 0
			powercfg /change monitor-timeout-dc 0
			
			# Enable guest account 
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableGuestAccount" -Value 1 

			# Enable guest account status & disable password complexity in gpedit.msc
			secedit /export /cfg tmp.inf >$null
			$content = Get-Content tmp.inf
			$content = $content -replace "PasswordComplexity = 1", "PasswordComplexity = 0"
			$content = $content -replace "EnableGuestAccount = 0", "EnableGuestAccount = 1"
			Set-Content tmp.inf -Value $content
			secedit /configure /db secedit.sdb /cfg tmp.inf >$null
			Remove-Item "tmp.inf", "secedit.sdb", "secedit.jfm"

			# Turn off UAC 
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0

			# Allow insecure guest auth
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 1

			# Allow insecure guest auth in gpedit.msc
			# TODO

			# Disable password expiration (reboot required)
			net accounts /maxpwage:unlimited >$null

			# Disable Ctrl+Alt+Del
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "disablecad" -Value 1

			# Rename computer (reboot requierd) - Press Enter to use the default setting
            $computer_name = Read-Host "Set computer name (press Enter to accept default: Win11-TC)"
            if ([string]::IsNullOrWhiteSpace($computer_name)) {
                $computer_name = "Win11-TC"
            }
            Rename-Computer -NewName $computer_name -Force >$null
            Write-Host "Computer name changed to $computer_name successfully."
			
			# Set password  - Press Enter to use the default setting
            $computer_password =  Read-Host "Set computer password (press Enter to accept default: 8888)" 
            if ([string]::IsNullOrWhiteSpace($computer_password)) {
                $computer_password = "8888"
            }
			cmd /c net user administrator $computer_password >$null
			Write-Host "Password changed to $computer_password successfully."

			# Define IP for NIC
			Get-NetAdapter -Physical | Where-Object { $_.Name -match "^Ethernet" }
			Write-Host ""
			$ip4 = Read-Host "Input IP4 address (press Enter to accept default: 192.168.1.1)"
            if ([string]::IsNullOrWhiteSpace($ip4)) {
                $ip4 = "192.168.1.1"
            }
			$ip6 = Read-Host "Input IP6 address (press Enter to accept default: 2001:db8::1)"
            if ([string]::IsNullOrWhiteSpace($ip6)) {
                $ip6 = "2001:db8::1"
            }
			
			# Disable DHCP
			Set-NetIPInterface -InterfaceAlias $NIC_interface -Dhcp Disabled >$null
			
			# Remove all existing IPv4 and IPv6 addresses
			Get-NetIPAddress -InterfaceAlias "$NIC_interface" -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false >$null
			Get-NetIPAddress -InterfaceAlias "$NIC_interface" -AddressFamily IPv6 | Remove-NetIPAddress -Confirm:$false >$null

			# Set new IPv4 & IPv6 address
			New-NetIPAddress -InterfaceAlias "$NIC_interface" -IPAddress $ip4 -PrefixLength 24 >$null
			Write-Host "IP4 address set to $ip4 successfully."
			New-NetIPAddress -InterfaceAlias "$NIC_interface" -IPAddress $ip6 -PrefixLength 64 >$null
			Write-Host "IP6 address set to $ip6 successfully."
			
            Write-Host ""
            Write-Host "**All is done!" -ForegroundColor Green
			Write-Host "**Remember to turn off the firewall after installing HLK Controller + Studio"
			Write-Host ""
			do {
				$choice = Read-Host "Do you want to reboot the system now? (y/n) "
				$choice = $choice.ToLower()
			} until ($choice -eq "y" -or $choice -eq "n")
			if ($choice -eq "y") {
				shutdown /r /t 0 >$null
                break
			} else {
				exit
            }
        }
        "s" {
            Write-Host "Now configuring HLK SUT..."
            # Set sleep & display off to Never
			powercfg /change standby-timeout-ac 0
			powercfg /change standby-timeout-dc 0
			powercfg /change monitor-timeout-ac 0
			powercfg /change monitor-timeout-dc 0
			
			# Turn off UAC 
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
			
			# Set IP
			Get-NetAdapter -Physical | Where-Object { $_.Name -match "^Ethernet" }
            Write-Host ""
            # $ip4_input = Read-Host "Input the last digit of the IP4 address (192.168.1.x)"
			$ip4 = Read-Host "Input IP4 address (press Enter to accept default: 192.168.1.2)"
            if ([string]::IsNullOrWhiteSpace($ip4)) {
                $ip4 = "192.168.1.2"
            }
			$ip6 = Read-Host "Input IP6 address (press Enter to accept default: 2001:db8::2)"
            if ([string]::IsNullOrWhiteSpace($ip6)) {
                $ip6 = "2001:db8::2"
            }
            $TC_ip6 = Read-Host "Input HLK server IP6 address as gateway (press Enter to accept default: 2001:db8::1)"
                     if ([string]::IsNullOrWhiteSpace($ip6)) {
                $TC_ip6 = "2001:db8::1"
            }

			# Disable DHCP
			Set-NetIPInterface -InterfaceAlias "$NIC_interface" -Dhcp Disabled >$null
			
			# Remove all existing IPv4 and IPv6 addresses
			Get-NetIPAddress -InterfaceAlias "$NIC_interface" -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false >$null
			Get-NetIPAddress -InterfaceAlias "$NIC_interface" -AddressFamily IPv6 | Remove-NetIPAddress -Confirm:$false >$null
			
			# Remove existing IPv6 gateway
			Get-NetRoute -InterfaceAlias "$NIC_interface" -AddressFamily IPv6 | Remove-NetRoute -Confirm:$false >$null
			
			# Set new IPv4 & IPv6 address/gateway
			New-NetIPAddress -InterfaceAlias "$NIC_interface" -IPAddress $ip4 -PrefixLength 24 >$null
			Write-Host "IP4 address set to $ip4 successfully."
			New-NetIPAddress -InterfaceAlias "$NIC_interface" -IPAddress $ip6 -PrefixLength 64 -DefaultGateway $server_ip6 >$null
			Write-Host "IP6 address set to $ip6 successfully."
			Write-Host "IP6 gateway set to $TC_ip6 successfully."
			
			Write-Host ""
            Write-Host "**All is done!" -ForegroundColor Green
			Write-Host "**Remember to turn off the firewall after installing HLK"
			Write-Host ""
			pause
            break 
        }
        "q" {
            break
        }
		"u" {
			do {
				Write-Host "This option will remove everything about HLK from the system, continue? (y/n)" -ForegroundColor Yellow
				$uninstall = Read-Host
				$uninstall = $uninstall.ToLower()
			} until ($uninstall -eq "y" -or $uninstall -eq "n")
			if ($uninstall -eq "y") {
				# Uninstall all HLK related programs
				# Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Windows Hardware Lab Kit Client*" -or $_.Name -like "*Application Verifier*" -or $_.Name -like "*WPT*" -or $_.Name -like "*WDTF*" -or $_.Name -like "*HLK*" -or $_.Name -like "*Debuggers*" } | Select-Object -Property Name, Version
				Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Windows Hardware Lab Kit Client*" } | ForEach-Object { $_.Uninstall() }
				Write-Host "Main HLK program removed successfully."
				Write-Host ""
				Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Application Verifier*" -or $_.Name -like "*WPT*" -or $_.Name -like "*WDTF*" -or $_.Name -like "*HLK*" -or $_.Name -like "*Debuggers*" } | ForEach-Object { $_.Uninstall() }
				Write-Host "Additional HLK patches removed successfully."
				
				# Delete all HLK related directories
				$paths = "C:\HLK", "C:\Program Files\Windows Kits", "C:\Program Files (x86)\Application Verifier", "C:\Program Files\Application Verifier"
				foreach ($path in $paths) {
				if (Test-Path $path) {
					Remove-Item -Path $path -Recurse -Force
					}
				}
				Write-Host "All HLK directories removed successfully."
				
				# Delete DTMLLUAdminUser account
				Remove-LocalUser -Name "DTMLLUAdminUser"
				Write-Host "DTMLLUAdminUser account deleted successfully."
				
				# Delete DTMLLUAdminUser account folder
				# Remove-Item -Path "C:\Users\DTMLLUAdminUser" -Recurse -Force
				
				# Turn on firewall
				netsh advfirewall set allprofiles state on >$null
				Write-Host "Firewall is turned on successfully."
				Write-Host ""
				Write-Host "**All is done!" -ForegroundColor Green
				Write-Host "**Remember to delete 'C:\Users\DTMLLUAdminUser' folder after signing out"
				Write-Host ""
				do {
					$choice = Read-Host "Sign out the DTMLLUAdminUser account now? (y/n) "
					$choice = $choice.ToLower()
				} until ($choice -eq "y" -or $choice -eq "n")
				if ($choice -eq "y") {
					shutdown /l
					break
				} else {
					exit
				}
			} else {
				break
            }
        }
        default {
            Write-Host "Invalid input."
        }
    }
} until ($choice -in "s", "c", "q", "u")

