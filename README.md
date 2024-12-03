# One-click to configure test environments for HLK server/client
#### Generally, the script does the following:
 1. Change computer name to `HLK` (server only)
 2. Change password to `8888` (server only)
 3. Disable DNS
 4. Set IPv4/IPv6 address (default: `192.168.1.1` for server)

### [How To Use]
+ Install Windows Server on the host
+ Double click on `HLKConfig.ps1` and input required data
+ Manually install HLK
+ Manual turn off firewall after installing HLK

