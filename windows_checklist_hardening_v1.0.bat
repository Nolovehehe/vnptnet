@ECHO OFF
REM /*************************************************************************
REM * 
REM 
REM *************************************************************************
REM * File information
REM * Author: Phuong Nguyen
REM * Company  Vnpt Net
REM * version 1.0
REM * created 04/07/2021
REM * description: This batch file reveals OS, hardware, and networking configuration.
REM * Known bugs:
REM *	1.
REM *	2.

:: This batch file reveals OS, hardware, and networking configuration.
TITLE Checklist windows hardening 
ECHO Please wait... Checking system information.

ECHO Get System Information
echo IP Address
ipconfig | findstr /R "IPv4"
echo System Hostname
hostname
echo.
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"OS Configuration" /C:"Original Install Date" /C:"Total Physical Memory" /C:"Domain" /C:"Logon Server" /C:"Hotfix(s)" /C:"Network Card(s)" 
echo.
echo Get all user
powershell -Command "Get-WmiObject Win32_UserAccount | Select-Object Name,FullName,Disabled"

echo Members of local administrator group on local computer
net localgroup administrators
echo.
echo Get list of startup services
net start
echo.
echo List port open
netstat -ab
echo End
echo.
echo 1. Chinh sach tai khoan
echo 1.1 Chinh sach mat khau
set tempfile="tmp_sec.txt"
if exist %tempfile% (
	del %tempfile%
)

SecEdit.exe /export /areas SECURITYPOLICY USER_RIGHTS /cfg %tempfile%
rem type %tempfile% 

echo 1.1.1 Cau hinh khong su dung lai n lan mat khau cu gan nhat Enforce password history khuyen nghi: ^>= 24
powershell -Command "Get-Content -Path %tempfile% | select -First 19" | findstr /c:"PasswordHistorySize" 
echo 1.1.2 Cau hinh thoi gian doi mat khau toi da MaximumPasswordAge khuyen nghi: ^<= 60  
powershell -Command "Get-Content -Path %tempfile% | select -First 19" | findstr /c:"MaximumPasswordAge"
echo 1.1.3 Cau hinh thoi gian doi mat khau toi thieu Minimum password age khuyen nghi: ^>= 1
powershell -Command "Get-Content -Path %tempfile% | select -First 19" | findstr /c:"MinimumPasswordAge"
echo 1.1.4 Cau hinh do dai mat khau toi thieu Minimum password length khuyen nghi: ^>= 14
powershell -Command "Get-Content -Path %tempfile% | select -First 19" | findstr /c:"MinimumPasswordLength"
echo 1.1.5 Cau hinh do phuc tap cua mat khau password policy meet complexity PasswordComplexity = 1 is Enable 
powershell -Command "Get-Content -Path %tempfile% | select -First 19" | findstr /c:"PasswordComplexity" 
echo.
echo 1.2 Chinh sach khoa tai khoan
echo 1.2.1 Cau hinh Thoi gian Khoa tai khoan neu dang nhap sai nhieu lan Account Lockout Duration khuyen nghi: ^>= 15
powershell -Command "Get-Content -Path %tempfile% | select -First 19" | findstr /c:"LockoutDuration" 
echo 1.2.2 Gioi han so lan dang nhap sai vao he thong Account lockout threshold khuyen nghi: ^<= 10
powershell -Command "Get-Content -Path %tempfile% | select -First 19" | findstr /c:"LockoutBadCount" 
echo 1.2.3 Cau thoi gian co the login lai ResetLockoutCount khuyen nghi: ^>= 15
powershell -Command "Get-Content -Path %tempfile% | select -First 19" | findstr /c:"ResetLockoutCount" 
if exist %tempfile% (
	del %tempfile%
) else (
   	echo file %tempfile% doesn't exist
)
echo.

echo 2. Cau hinh an ninh Windows Firewall (Advanced)
echo 2.1. Domain Profile
echo 2.1.1. Thiet lap trang thai Windows Firewall: Domain: Firewall state
netsh advfirewal show Domainprofile state

echo 2.1.2. Thiet lap trang thai Windows Firewall: Domain: Inbound connections
powershell -Command "Get-NetFirewallRule | where {$_.Enabled -eq 'True' -AND $_.Profile -Like '*Domain*' -AND $_.Direction -eq 'Inbound'} | Select-Object DisplayName, Description, DisplayGroup, Group, Enabled, Profile, Platform, Direction, Action, EdgeTraversalPolicy, LooseSourceMapping, LocalOnlyMapping, Owner, PrimaryStatus, Status, EnforcementStatus, PolicyStoreSource, PolicyStoreSourceType"

echo 2.1.3. Thiet lap trang thai Windows Firewall: Domain: Outbound connections
powershell -Command "Get-NetFirewallRule | where {$_.Enabled -eq 'True' -AND $_.Profile -Like '*Domain*' -AND $_.Direction -eq 'Outbound'} | Select-Object DisplayName, Description, DisplayGroup, Group, Enabled, Profile, Platform, Direction, Action, EdgeTraversalPolicy, LooseSourceMapping, LocalOnlyMapping, Owner, PrimaryStatus, Status, EnforcementStatus, PolicyStoreSource, PolicyStoreSourceType"

echo 2.1.4. Cau hinh vi tri luu tru nhat ky Windows Firewall: Domain: Logging: Name Remediation:%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log
powershell -Command "netsh advfirewal show Domainprofile logging"

echo 2.1.5. Cau hinh kich thuoc gioi han Windows Firewall: Domain: Logging: khuyen nghi: ^>= 16,384 KB
powershell -Command "netsh advfirewal show Domainprofile logging | findstr MaxFileSize"

echo 2.1.6. Thiet lap chinh sach Windows Firewall: Domain: Logging: Log dropped packets khuyen nghi: Enable
powershell -Command "netsh advfirewal show Domainprofile logging | findstr LogDroppedConnections"

echo 2.1.7. Thiet lap chinh sach Windows Firewall: Domain: Logging: Log successful connections khuyen nghi: Enable
powershell -Command "netsh advfirewal show Domainprofile logging | findstr LogAllowedConnections"

echo.
echo 2.2. Private Profile
echo 2.2.1. Thiet lap trang thai Windows Firewall: Private: Firewall state
netsh advfirewal show Privateprofile state
echo 2.2.2. Thiet lap trang thai Windows Firewall: Private: Inbound connections
powershell -Command "Get-NetFirewallRule | where {$_.Enabled -eq 'True' -AND $_.Profile -Like '*Private*' -AND $_.Direction -eq 'Inbound'} | Select-Object DisplayName, Description, DisplayGroup, Group, Enabled, Profile, Platform, Direction, Action, EdgeTraversalPolicy, LooseSourceMapping, LocalOnlyMapping, Owner, PrimaryStatus, Status, EnforcementStatus, PolicyStoreSource, PolicyStoreSourceType"

echo 2.2.3. Thiet lap trang thai Windows Firewall: Private: Outbound connections
powershell -Command "Get-NetFirewallRule | where {$_.Enabled -eq 'True' -AND $_.Profile -Like '*Private*' -AND $_.Direction -eq 'Outbound'} | Select-Object DisplayName, Description, DisplayGroup, Group, Enabled, Profile, Platform, Direction, Action, EdgeTraversalPolicy, LooseSourceMapping, LocalOnlyMapping, Owner, PrimaryStatus, Status, EnforcementStatus, PolicyStoreSource, PolicyStoreSourceType"

echo 2.2.4. Cau hinh vi tri luu tru nhat ky Windows Firewall: Private: Logging: Name Remediation:%SystemRoot%\System32\logfiles\firewall\privatefw.log
powershell -Command "netsh advfirewal show Privateprofile logging"

echo 2.2.5. Cau hinh kich thuoc gioi han Windows Firewall: Private: Logging: khuyen nghi: ^>= 16,384 KB
powershell -Command "netsh advfirewal show Privateprofile logging | findstr MaxFileSize"

echo 2.2.6. Thiet lap chinh sach Windows Firewall: Private: Logging: Log dropped packets khuyen nghi: Enable
powershell -Command "netsh advfirewal show Privateprofile logging | findstr LogDroppedConnections"

echo 2.2.7. Thiet lap chinh sach Windows Firewall: Private: Logging: Log successful connections khuyen nghi: Enable
powershell -Command "netsh advfirewal show Privateprofile logging | findstr LogAllowedConnections"
echo.

echo 2.3. Public Profile
echo 2.2.1. Thiet lap trang thai Windows Firewall: Public: Firewall state
netsh advfirewal show Publicprofile state
echo 2.2.2. Thiet lap trang thai Windows Firewall: Public: Inbound connections
powershell -Command "Get-NetFirewallRule | where {$_.Enabled -eq 'True' -AND $_.Profile -Like '*Public*' -AND $_.Direction -eq 'Inbound'} | Select-Object DisplayName, Description, DisplayGroup, Group, Enabled, Profile, Platform, Direction, Action, EdgeTraversalPolicy, LooseSourceMapping, LocalOnlyMapping, Owner, PrimaryStatus, Status, EnforcementStatus, PolicyStoreSource, PolicyStoreSourceType"

echo 2.2.3. Thiet lap trang thai Windows Firewall: Public: Outbound connections
powershell -Command "Get-NetFirewallRule | where {$_.Enabled -eq 'True' -AND $_.Profile -Like '*Public*' -AND $_.Direction -eq 'Outbound'} | Select-Object DisplayName, Description, DisplayGroup, Group, Enabled, Profile, Platform, Direction, Action, EdgeTraversalPolicy, LooseSourceMapping, LocalOnlyMapping, Owner, PrimaryStatus, Status, EnforcementStatus, PolicyStoreSource, PolicyStoreSourceType"

echo 2.2.4. Cau hinh vi tri luu tru nhat ky Windows Firewall: Public: Logging: Name Remediation:%SystemRoot%\System32\logfiles\firewall\privatefw.log
powershell -Command "netsh advfirewal show Publicprofile logging"

echo 2.2.5. Cau hinh kich thuoc gioi han Windows Firewall: Public: Logging: khuyen nghi: ^>= 16,384 KB
powershell -Command "netsh advfirewal show Publicprofile logging | findstr MaxFileSize"

echo 2.2.6. Thiet lap chinh sach Windows Firewall: Public: Logging: Log dropped packets khuyen nghi: Enable
powershell -Command "netsh advfirewal show Publicprofile logging | findstr LogDroppedConnections"

echo 2.2.7. Thiet lap chinh sach Windows Firewall: Public: Logging: Log successful connections khuyen nghi: Enable
powershell -Command "netsh advfirewal show Publicprofile logging | findstr LogAllowedConnections"
echo.

echo 3.	Tep mau quan tri chinh sach nhom
echo 3.1. Cau hinh chinh sach AutoPlay
echo 3.1.1. Cau hinh chinh sach Disallow Autoplay for non-volume devices 
REG QUERY HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer

echo 3.1.2. Cau hinh chinh sach Set the default behavior for AutoRun
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer

echo 3.1.3. Cau hinh chinh sach Turn off Autoplay
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
echo.

echo 4.	Cai dat va cap nhat cac ban va bao mat
echo 4.1. Cai dat va cap nhat cac ban va bao mat
echo 4.1.1. Get list update 
wmic qfe list brief /format:texttablewsys
echo.

echo 5.	Kiem tra cai dat phan mem Anti-virus 
wmic product get name,version | findstr Kaspersky

echo 5.1. Kiem tra trang thai phan mem
tasklist | findstr avp

echo 5.2. Kiem tra tinh nang tu dong cap nhat cua phan mem 	
"C:\Program Files (x86)\Kaspersky Lab\Kaspersky Endpoint Security for Windows\avp.com" status

echo 5.3. Thuc hien lich quet dinh ky may chu

echo 5.4. Check service SMB 
powershell -Command "Get-SmbServerConfiguration | Select EnableSMB1Protocol,EnableSMB2Protocol" 

echo.
echo 6. Kiem tra Windows Defender
echo 6.1 Kiem tra trang thai
C:\Windows\System32\cmd.exe /k C:\Windows\System32\sc.exe query windefend

echo 6.2 Kiem tra version
C:\Windows\System32\cmd.exe /k C:\Windows\System32\sc.exe qc windefend

@echo on
