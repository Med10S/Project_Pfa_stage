#!/bin/bash

# Block all traffic except for Wazuh manager (replace MANAGER_IP)
MANAGER_IP="192.168.15.3"
iptables -F
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -A INPUT -s $MANAGER_IP -j ACCEPT
iptables -A OUTPUT -d $MANAGER_IP -j ACCEPT
# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

logger "OSSEC: Network disabled except for manager $MANAGER_IP"
exit 0
