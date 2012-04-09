sc stop npf
sc delete npf
del %windir%\system32\packet.dll /f /q
del %windir%\system32\pthreadvc.dll /f /q
del %windir%\system32\wanpacket.dll /f /q
del %windir%\system32\wpcap.dll /f /q
del %windir%\system32\drivers\npf.sys /f /q
echo winpacpÉ¾³ýÍê³É
pause
