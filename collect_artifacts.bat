@echo off
set /p investigation="Enter investigation name: "
set /p disk="Enter Disk containing evidence: "

:: Create folder tree
echo Creating folder tree
MkDir "C:\Cases\%investigation%\Analysis\"
MkDir "C:\Cases\%investigation%\Analysis\User_Activities\"
MkDir "C:\Cases\%investigation%\Analysis\User_Activities\Cache\"
MkDir "C:\Cases\%investigation%\Analysis\User_Activities\Link_Files\"
MkDir "C:\Cases\%investigation%\Analysis\User_Activities\Jump_Lists\"
MkDir "C:\Cases\%investigation%\Analysis\Host_Information\"
MkDir "C:\Cases\%investigation%\Analysis\EventLogs\"
MkDir "C:\Cases\%investigation%\Analysis\Execution\"
MkDir "C:\Cases\%investigation%\Analysis\Execution\Amcache\"
MkDir "C:\Cases\%investigation%\Analysis\Execution\Prefetch\"
MkDir "C:\Cases\%investigation%\Analysis\Exports\"
MkDir "C:\Cases\%investigation%\Analysis\Memory\"
MkDir "C:\Cases\%investigation%\Analysis\Memory\dll\"
MkDir "C:\Cases\%investigation%\Analysis\NTFS\"
MkDir "C:\Cases\%investigation%\Analysis\NTFS\MFT\"
MkDir "C:\Cases\%investigation%\Analysis\Registry\"
MkDir "C:\Cases\%investigation%\Analysis\Timeline\"
 
MkDir "C:\Cases\%investigation%\Evidence\"
 
MkDir "C:\Cases\%investigation%\Kape\"

:: Run KAPE
echo Run KAPE
cd "C:\Tools\KAPE\"
.\kape.exe --tsource %disk%: --tdest C:\Cases\%investigation%\Kape --tflush --target KapeTriage --msource C:\Cases\%investigation%\Kape --mdest C:\Cases\%investigation%\Analysis\Modules --mflush --module !EZParser --gui

:: Copy registry hives from evidence
echo Copy registry hives
xcopy "C:\Cases\%investigation%\Kape\%disk%\Windows\System32\config\" "C:\Cases\%investigation%\Analysis\Registry\" /H

:: Show Users on disk
cd /d "%disk%:\Users\"
dir /b /o:n /ad-h
set /p useraccount="Name of user account in evidence: "

:: User hives
echo Copy User hives
cd /d "C:\"
xcopy "C:\Cases\%investigation%\Kape\%disk%\Users\%useraccount%\AppData\Local\Microsoft\Windows\UsrClass.dat" "C:\Cases\%investigation%\Analysis\Registry\" /H
xcopy "C:\Cases\%investigation%\Kape\%disk%\Users\%useraccount%\NTUSER.dat" "C:\Cases\%investigation%\Analysis\Registry\" /H

:: RegRipper
echo Run RegRipper
cd "C:\Cases\%investigation%\Analysis\Registry\"
attrib -h UsrClass.dat
attrib -h NTUSER.dat
for /r %%i in (*) do (C:\Tools\RegRipper3.0-master\rip.exe -r %%i -a > %%i.txt)

:: Acquire device information
cd "C:\Cases\%investigation%\Analysis\Registry\"
:: Hostname
C:\Tools\RegRipper3.0-master\rip.exe -r "SYSTEM" -p compname | findstr "ComputerName\ \ \ \ =" | findstr "ComputerName" > "C:\Cases\%investigation%\Analysis\Host_Information\Hostname.txt"
:: Windows version
C:\Tools\RegRipper3.0-master\rip.exe -r "SOFTWARE" -p winver > "C:\Cases\%investigation%\Analysis\Host_Information\WindowsVersion.txt"
:: Defender options
C:\Tools\RegRipper3.0-master\rip.exe -r "SOFTWARE" -p defender > "C:\Cases\%investigation%\Analysis\Host_Information\DefenderSettings.txt"
:: Timezone
C:\Tools\RegRipper3.0-master\rip.exe -r "SYSTEM" -p timezone > "C:\Cases\%investigation%\Analysis\Host_Information\Timezone.txt"
:: Profile List
C:\Tools\RegRipper3.0-master\rip.exe -r "SOFTWARE" -p profilelist > "C:\Cases\%investigation%\Analysis\Host_Information\Profilelist.txt"
:: Network Information
C:\Tools\RegRipper3.0-master\rip.exe -r "SYSTEM" -p nic2 > "C:\Cases\%investigation%\Analysis\Host_Information\NetworkInformation.txt"
:: Shutdown time
C:\Tools\RegRipper3.0-master\rip.exe -r "SYSTEM" -p shutdown > "C:\Cases\%investigation%\Analysis\Host_Information\ShutdownTime.txt

:: MFTECmd
echo Run MFTECmd to parse MasterFileTable
cd "C:\Tools\EZTools\"
MFTECmd.exe -f "C:\Cases\%investigation%\Kape\%disk%\$MFT" --csv "C:\Cases\%investigation%\Analysis\NTFS\MFT" --csvf MFT.csv
echo Run MFTECmd to parse Journal
MFTECmd.exe -f "C:\Cases\%investigation%\Kape\%disk%\$Extend\$J" -m "C:\Cases\%investigation%\Kape\%disk%\$MFT" --csv "C:\Cases\%investigation%\Analysis\NTFS"

:: AppCompatCacheParser
echo Run AppCompatCacheParser
AppCompatCacheParser.exe -f "C:\Cases\%investigation%\Analysis\Registry\SYSTEM" --csv "C:\Cases\%investigation%\Analysis\Execution"

:: AmcacheParser
echo Run AmcacheParser
AmcacheParser.exe -f "C:\Cases\%investigation%\Kape\%disk%\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\Cases\%investigation%\Analysis\Execution\Amcache"

:: PECmd
echo Run PECmd
PECmd.exe -d "C:\Cases\%investigation%\Kape\%disk%\Windows\prefetch" --csv "C:\Cases\%investigation%\Analysis\Execution\Prefetch"

::EvtxECmd
echo Run EvtxECmd
cd "C:\Tools\EZTools\EvtxeCmd"
EvtxECmd.exe -d "C:\Cases\%investigation%\Kape\%disk%\Windows\System32\winevt\logs" --csv "C:\Cases\%investigation%\Analysis\EventLogs"

::WxTCmd
echo Run WxTCmd to parse ActivitiesCache
cd "C:\Tools\EZTools"
WxTCmd.exe -f "C:\Cases\%investigation%\Kape\%disk%\Users\%useraccount%\AppData\Local\ConnectedDevicesPlatform\L.%useraccount%\ActivitiesCache.db" --csv "C:\Cases\%investigation%\Analysis\User_Activities\Cache"

:: LECmd
echo Run LECmd to parse Link files
cd "C:\Tools\EZTools"
LECmd.exe -d "C:\Cases\%investigation%\Kape\%disk%\Users\%useraccount%\AppData\Roaming\Microsoft\Windows\Recent" --csv "C:\Cases\%investigation%\Analysis\User_Activities\Link_Files"

:: JLECmd
echo Run LECmd to parse Jump lists
cd "C:\Tools\EZTools"
JLECmd.exe -d "C:\Cases\%investigation%\Kape\%disk%\Users\%useraccount%\AppData\Roaming\Microsoft\Windows\Recent" --csv "C:\Cases\%investigation%\Analysis\User_Activities\Jump_Lists"

:: Copy history of executed commands
echo Copy history of executed commands
cd /d "C:\"
xcopy "C:\Cases\%investigation%\Kape\%disk%\Users\%useraccount%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" "C:\Cases\%investigation%\Analysis\User_Activities\"  /H


echo Done!
set /p=Hit ENTER to continue...
timeout 5 > NUL
