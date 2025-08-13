:: C:\Program Files (x86)\ossec-agent\active-response\bin\disable-network.cmd
@echo off
set MANAGER_IP=192.168.15.3
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall firewall add rule name="AllowManager" dir=out action=allow remoteip=%MANAGER_IP%
netsh advfirewall firewall add rule name="AllowManagerIn" dir=in action=allow remoteip=%MANAGER_IP%
eventcreate /T WARNING /ID 1000 /L APPLICATION /D "OSSEC: Network disabled except for manager"
