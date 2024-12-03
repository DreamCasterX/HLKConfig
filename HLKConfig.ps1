
do {
    Clear-Host
	Write-Host "[HLK Auto Configuration Tool  v1.0]"
	Write-Host ""
    $choice = Read-Host "Are you setting a HLK (c)Client or (s)Server ? "
    $choice = $choice.ToLower()

    switch ($choice) {
        "s" {
            Write-Host "Now configuring HLK Server..."
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

			# Rename computer (reboot requierd)
			Rename-Computer -NewName HLK >$null
			Write-Host "Computer name changed to HLK successfully."
			
			# Set password
			cmd /c net user administrator 8888 >$null
			Write-Host "Password changed to 8888 successfully."

			# Set IP (Default interface:Ethernet    IP4:192.168.1.1    IP6:2001:db8::1)
			Get-NetAdapter -Physical | Where-Object { $_.Name -match "^Ethernet" }
			Write-Host ""
			# $ip4 = Read-Host "Input IP4 address (192.168.1.x)"
			# $ip6 = Read-Host "Input IP6 address (2001:db8::x)"
			$ip4 = "192.168.1.1"
			$ip6 = "2001:db8::1"
			
			# Disable DHCP
			Set-NetIPInterface -InterfaceAlias "Ethernet" -Dhcp Disabled >$null
			
			# Remove all existing IPv4 and IPv6 addresses
			Get-NetIPAddress -InterfaceAlias "Ethernet" -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false >$null
			Get-NetIPAddress -InterfaceAlias "Ethernet" -AddressFamily IPv6 | Remove-NetIPAddress -Confirm:$false >$null

			# Set new IPv4 & IPv6 address
			New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $ip4 -PrefixLength 24 >$null
			Write-Host "IP4 address set to $ip4 successfully."
			New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $ip6 -PrefixLength 64 >$null
			Write-Host "IP6 address set to $ip6 successfully."
			
            Write-Host ""
            Write-Host "**All is done!"
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
        "c" {
            Write-Host "Now configuring HLK Client..."
            # Turn off UAC 
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
			
			# Set IP (Default interface:Ethernet    IP4:192.168.1.x    IP6:2001:db8::x    IP6 gateway:2001:db8::1)
			Get-NetAdapter -Physical | Where-Object { $_.Name -match "^Ethernet" }
			Write-Host ""
			# $ip4 = Read-Host "Input IP4 address (192.168.1.x)"
			# $ip6 = Read-Host "Input IP6 address (2001:db8::x)"
			# $server_ip6 = Read-Host "Input HLK server IP6 address (2001:db8::x)"
			$ip4_input = Read-Host "Input the last digit of the IP4 address (192.168.1.x)"
			$ip4 = "192.168.1.$ip4_input"
			$ip6 = "2001:db8::$ip4_input"
			$server_ip6 = "2001:db8::1"
			
			# Disable DHCP
			Set-NetIPInterface -InterfaceAlias "Ethernet" -Dhcp Disabled >$null
			
			# Remove all existing IPv4 and IPv6 addresses
			Get-NetIPAddress -InterfaceAlias "Ethernet" -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false >$null
			Get-NetIPAddress -InterfaceAlias "Ethernet" -AddressFamily IPv6 | Remove-NetIPAddress -Confirm:$false >$null
			
			# Remove existing IPv6 gateway
			Get-NetRoute -InterfaceAlias "Ethernet" -AddressFamily IPv6 | Remove-NetRoute -Confirm:$false >$null
			
			# Set new IPv4 & IPv6 address/gateway
			New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $ip4 -PrefixLength 24 >$null
			Write-Host "IP4 address set to $ip4 successfully."
			New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $ip6 -PrefixLength 64 -DefaultGateway $server_ip6 >$null
			Write-Host "IP6 address set to $ip6 successfully."
			Write-Host "IP6 gateway set to $server_ip6 successfully."
			
			Write-Host ""
            Write-Host "**All is done!"
			Write-Host "**Remember to turn off the firewall after installing HLK Client"
			Write-Host ""
			pause
            break 
        }
        "q" {
            break
        }
        default {
            Write-Host "Invalid input."
        }
    }
} until ($choice -in "s", "c", "q")





