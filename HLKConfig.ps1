
$creator = "Mike Lu"
$change_date = "8/7/2025"
$version = "1.0"

# [Note] 
# Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned` first if the script is restriced


# User-defined settings
$time_zone = 'Taipei Standard Time'



# Ensure the scipt is run with administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb RunAs -ArgumentList $arguments
    exit
}


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

			# Disable password expiration (reboot required)
			net accounts /maxpwage:unlimited >$null

			# Disable Ctrl+Alt+Del
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "disablecad" -Value 1

            # Set local time zone
            Set-TimeZone -Name "$time_zone"
            
			# Rename computer (reboot requierd)
            $computer_name = Read-Host "Set computer name (press Enter to accept default: [HLK])"
            if ([string]::IsNullOrWhiteSpace($computer_name)) { $computer_name = "HLK" }
            Rename-Computer -NewName $computer_name -Force >$null
            Write-Host "Computer name changed to $computer_name successfully."
			
			# Set password
            $computer_password =  Read-Host "Set computer password (press Enter to accept default: [8888])" 
            if ([string]::IsNullOrWhiteSpace($computer_password)) { $computer_password = "8888" }
			cmd /c net user administrator $computer_password >$null
			Write-Host "Password changed to $computer_password successfully."

			# Get network adpter interface to use
			# Get-NetAdapter -Physical | Where-Object { $_.Name -match "^Ethernet" }  # Only display Ethernet
            $adapters = Get-NetAdapter -Physical
            $adapterCount = ($adapters | Measure-Object).Count
            
            $adapters | ForEach-Object {
                [PSCustomObject]@{
                    No = [array]::IndexOf($adapters, $_) + 1
                    Name = $_.Name
                    InterfaceDescription = $_.InterfaceDescription
                    Status = $_.Status
                    MacAddress = $_.MacAddress
                    LinkSpeed = $_.LinkSpeed
                }
            } | Format-Table -AutoSize
            $validSelection = $false
            
            while (-not $validSelection) {
                $selection = Read-Host "Input network adapter number (press Enter to accept default: [1])"
                if ([string]::IsNullOrWhiteSpace($selection)) {
                    $selection = 1
                    $validSelection = $true
                } elseif ($selection -match "^\d+$" -and $selection -ge 1 -and $selection -le $adapterCount) {
                    $validSelection = $true
                }
            }
            $selectedAdapter = $adapters[$selection - 1].Name
            Write-Host "Selected adapter: $selectedAdapter"

            # Get current IPv4 address of the selected adapter
            $currentIP = (Get-NetIPAddress -InterfaceAlias $selectedAdapter -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
            if (-not $currentIP) { $currentIP = "192.168.1.1" }

            # Ask users to input IP4 and IP6 addresses
			Write-Host ""
			$ip4 = Read-Host "Input IP4 address (press Enter to accept default: [$currentIP])"
            if ([string]::IsNullOrWhiteSpace($ip4)) { $ip4 = $currentIP }
			$ip6 = Read-Host "Input IP6 address (press Enter to accept default: [2001:db8::1])"
            if ([string]::IsNullOrWhiteSpace($ip6)) { $ip6 = "2001:db8::1" }
			
			# Disable DHCP
			Set-NetIPInterface -InterfaceAlias "$selectedAdapter" -Dhcp Disabled >$null
			
			# Clear existing IPv4 and IPv6 addresses
			Get-NetIPAddress -InterfaceAlias "$selectedAdapter" -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue >$null
			Get-NetIPAddress -InterfaceAlias "$selectedAdapter" -AddressFamily IPv6 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue >$null

			# Set new IPv4 & IPv6 address
            Write-Host ""
			New-NetIPAddress -InterfaceAlias "$selectedAdapter" -IPAddress $ip4 -PrefixLength 24 >$null
			Write-Host "IP4 address set to $ip4 successfully."
			New-NetIPAddress -InterfaceAlias "$selectedAdapter" -IPAddress $ip6 -PrefixLength 64 >$null
			Write-Host "IP6 address set to $ip6 successfully."
			
            # Turn off firewall
            netsh advfirewall set allprofiles state off > $null 2>&1
            
            Write-Host ""
            Write-Host "**All is done!" -ForegroundColor Green
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
			
			# Allow insecure guest auth
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 1

			# Allow insecure guest auth in gpedit.msc (Function works but GUI does not change)
            Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force
            
            # Workaround for error "An Extended Error Has Occurred" during SMB communication on Windows 11
            Set-SmbClientConfiguration -RequireSecuritySignature $false -Force
            
            # Set local time zone
            Set-TimeZone -Name "$time_zone"
            
            # Rename computer (reboot requierd)
            $computer_name = Read-Host "Set computer name (press Enter to accept default: [Win11-SUT])"
            if ([string]::IsNullOrWhiteSpace($computer_name)) { $computer_name = "Win11-SUT" }
            Rename-Computer -NewName $computer_name -Force >$null
            Write-Host "Computer name changed to $computer_name successfully."
            
			# Get network adpter interface to use
			# Get-NetAdapter -Physical | Where-Object { $_.Name -match "^Ethernet" }  # Only display Ethernet
            $adapters = Get-NetAdapter -Physical
            $adapterCount = ($adapters | Measure-Object).Count
            
            $adapters | ForEach-Object {
                [PSCustomObject]@{
                    No = [array]::IndexOf($adapters, $_) + 1
                    Name = $_.Name
                    InterfaceDescription = $_.InterfaceDescription
                    Status = $_.Status
                    MacAddress = $_.MacAddress
                    LinkSpeed = $_.LinkSpeed
                }
            } | Format-Table -AutoSize
            $validSelection = $false
            
            while (-not $validSelection) {
                $selection = Read-Host "Input network adapter number (press Enter to accept default: [1])"
                if ([string]::IsNullOrWhiteSpace($selection)) {
                    $selection = 1
                    $validSelection = $true
                } elseif ($selection -match "^\d+$" -and $selection -ge 1 -and $selection -le $adapterCount) {
                    $validSelection = $true
                }
            }
            $selectedAdapter = $adapters[$selection - 1].Name
            Write-Host "Selected adapter: $selectedAdapter"
            
            # Get current IPv4 address of the selected adapter
            $currentIP = (Get-NetIPAddress -InterfaceAlias $selectedAdapter -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
            if (-not $currentIP) { $currentIP = "192.168.1.2" }

            Write-Host ""
            # $ip4_input = Read-Host "Input the last digit of the IP4 address (192.168.1.x)"
			$ip4 = Read-Host "Input IP4 address (press Enter to accept default: [$currentIP])"
            if ([string]::IsNullOrWhiteSpace($ip4)) { $ip4 =  $currentIP }
			$ip6 = Read-Host "Input IP6 address (press Enter to accept default: [2001:db8::2])"
            if ([string]::IsNullOrWhiteSpace($ip6)) { $ip6 = "2001:db8::2" }
            $TC_ip6 = Read-Host "Input HLK server IP6 address as gateway (press Enter to accept default: [2001:db8::1])"
            if ([string]::IsNullOrWhiteSpace($TC_ip6)) { $TC_ip6 = "2001:db8::1" }

			# Disable DHCP
			Set-NetIPInterface -InterfaceAlias "$selectedAdapter" -Dhcp Disabled >$null
			
			# Clear existing IPv4 and IPv6 addresses
			Get-NetIPAddress -InterfaceAlias "$selectedAdapter" -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue >$null
			Get-NetIPAddress -InterfaceAlias "$selectedAdapter" -AddressFamily IPv6 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue >$null
			
			# Clear existing IPv6 gateway
			Get-NetRoute -InterfaceAlias "$selectedAdapter" -AddressFamily IPv6 -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue >$null
			
			# Set new IPv4 & IPv6 address/gateway
            Write-Host ""
			New-NetIPAddress -InterfaceAlias "$selectedAdapter" -IPAddress $ip4 -PrefixLength 24 >$null
			Write-Host "IP4 address set to $ip4 successfully."
			New-NetIPAddress -InterfaceAlias "$selectedAdapter" -IPAddress $ip6 -PrefixLength 64 -DefaultGateway $TC_ip6 >$null
			Write-Host "IP6 address set to $ip6 successfully."
			Write-Host "IP6 gateway set to $TC_ip6 successfully."
			
            # Turn off firewall
            netsh advfirewall set allprofiles state off > $null 2>&1
            
			Write-Host ""
            Write-Host "**All is done!" -ForegroundColor Green
			# Write-Host "**Remember to turn off the firewall after installing the HLK"
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
} until ($choice -in "s", "t", "q", "u")

