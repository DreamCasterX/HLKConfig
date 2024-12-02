
do {
    Clear-Host
	Write-Host "[HLK Auto Configuration Tool  v1.0]"
	Write-Host ""
    $choice = Read-Host "Are you setting a HLK (c)Client or (s)Server ? "
    $choice = $choice.ToLower()

    switch ($choice) {
        "s" {
            # Server Configuration
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

			# 手動設定 IP (請替換 "Ethernet" 為您的網路介面卡名稱)
			Get-NetAdapter -Physical | Where-Object { $_.Name -match "^Ethernet" }
			Write-Host ""
			$ip4 = Read-Host "Input IP4 address (192.168.1.x)"
			$ip6 = Read-Host "Input IP6 address (2001:db8::x)"
			Set-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $ip4 -PrefixLength 24 >$null
			Set-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $ip6 -PrefixLength 64 >$null


            Write-Host ""
            Write-Host "**All is done!**"
			Write-Host "Remember to turn off the firewall after installing HLK controller + studio"
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
            # Client Configuration
            Write-Host "Now configuring HLK Client..."
			
            # Turn off UAC 
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
			
			# 手動設定 IP (請替換 "Ethernet" 為您的網路介面卡名稱)
			Get-NetAdapter -Physical | Where-Object { $_.Name -match "^Ethernet" }
			Write-Host ""
			$ip4 = Read-Host "Input IP4 address (192.168.1.x)"
			$ip6 = Read-Host "Input IP6 address (2001:db8::x)"
			Set-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $ip4 -PrefixLength 24 >$null
			Set-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $ip6 -PrefixLength 64 >$null
			
			Write-Host ""
            Write-Host "**All is done!**"
			Write-Host "Remember to turn off the firewall after installing HLK client"
			Write-Host ""
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





