#!/bin/bash

# Restore default networking
iptables -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT

logger "OSSEC: Network enabled (restored)"
exit 0
