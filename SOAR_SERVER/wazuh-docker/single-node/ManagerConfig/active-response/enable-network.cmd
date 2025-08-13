:: C:\Program Files (x86)\ossec-agent\active-response\bin\enable-network.cmd
@echo off
netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound
netsh advfirewall firewall delete rule name="AllowManager"
netsh advfirewall firewall delete rule name="AllowManagerIn"
eventcreate /T INFORMATION /ID 1001 /L APPLICATION /D "OSSEC: Network enabled (restored)"
