#!/bin/bash

# Iptable firewall rules for configuring port knocking of a tcp connection on a service port
# specified below, e.g. a SSH connection. The firewall checks if a client sends traffic to
# port1 and port2 in sequence and then opens the service port for the client for
# delay_interval seconds. The traffic to port1 and port2 has to be sent within seq_interval
# number of seconds of eachother.

# The ports needed for knocking
port1=5997
port2=5959
service_port=22
delay_interval=200
seq_interval=20

# First we flush all redefined rules from the iptables
iptables -F

# Uncomment if you want the script to remove all non-built-in chains from the table
iptables -X

# Set all built-in chains, in the 'filter' table, to the ACCEPT policy
# meaning that if their evaluation reaches the end of the chain, the
# traffic is accepted.
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# At this point we have a completely open firewall that we can begin
# to restrict.

# Create new chains in the 'filter' table
iptables -N WALL
iptables -N GATE1
iptables -N GATE2
iptables -N PASSED

# Allow already established connections through
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow connections from the local machine
iptables -A INPUT -i lo -j ACCEPT

# Uncomment to allow tcp connections on port 80
#iptables -A INPUT -p tcp --dport 80 -j ACCEPT
# Uncomment to allow udp connection on port 51820 for wireguard
#iptables -A INPUT -p udp --dport 51820 -j ACCEPT

# Finally in the INPUT chain we transfer control to the rules in the WALL chain.
iptables -A INPUT -j WALL


# ---------------------------------------------------------------------------
# Configuring the WALL

# Uncomment to turn on logging for when any connection hits the wall
#iptables -A WALL -j LOG --log-prefix '*WALL Hit! '

# First we check to see if the client is authorized through the wall and in that case
# send them to the PASSED chain. The timing for how long the client is allowed to stay
# authenticated is configured by the delay_interval variables and is handled by the
# PASSED chain itself.
iptables -A WALL -m recent --rcheck --name AUTH2 -j PASSED

# Check if the client has already knocked on GATE1 within the seq_interval last seconds
# and send it to GATE2 in this case.
iptables -A WALL -m recent --rcheck --name AUTH1 --seconds $seq_interval -j GATE2

# If the client neither has knocked already on GATE1 nor the sequence GATE1, GATE2, then
# we send them to GATE1 to see if this is the first time that they knock correctly.
iptables -A WALL -j GATE1


# ---------------------------------------------------------------------------
# Configuring the 1st gate

# Remove the client from the list AUTH2 if it has previously been authenticated
# but something else has happened like that the timer for their port knocks ran out.
iptables -A GATE1 -p tcp --dport $port1 -m recent --name AUTH2 --remove

# Uncomment this line to allow logging of first knocks
iptables -A GATE1 -p tcp --dport $port1 -j LOG --log-prefix '*GATE1 knocked '

# We use the recent module to create a list AUTH1. If the traffic from the client
# is a tcp connection to 'port1', then we add the clients address to the list and
# then drop the traffic. In other words we add the client to the list of people
# who have passed the first knock.
iptables -A GATE1 -p tcp --dport $port1 -m recent --name AUTH1 --set -j DROP

# Uncomment this line to allow dropped connections attempts to be logged
iptables -A GATE1 -j LOG --log-prefix '*Connection dropped GATE1 '

# Drop all remaining traffic sent to the GATE1 chain
iptables -A GATE1 -j DROP

# ---------------------------------------------------------------------------
# Configuring the 2nd gate

# In this chain, we assume that the client has already been checked to be in the
# AUTH1 list, meaning that they already have previously knocked on port1.

# Remove the client from the previous list
iptables -A GATE2 -m recent --name AUTH1 --remove

# Uncomment this line to enable logging when the user gets added to the AUTH2 list
iptables -A GATE2 -p tcp --dport $port2 -j LOG --log-prefix '**Port opened! '

# Now that the client is removed from all 'recent' lists, we add them to the
# AUTH2 list if they have knocked on the second port.
iptables -A GATE2 -p tcp --dport $port2 -m recent --name AUTH2 --set -j DROP

# Remaining traffic is sent to GATE1 to check if it matches the first port, e.g.
# if a client knocks on port1 twice.
iptables -A GATE2 -j GATE1

# ---------------------------------------------------------------------------
# Configuring the PASSED chain

# In this chain we assume that the client is in the AUTH2 list, implying that they have
# already correctly knocked on gate1 and 2 in sequence within the time interval specified
# by seq_interval.

# If the client has correctly knocked, they are in the AUTH2 list. We delay removing them
# from this list for delay_interval number of seconds. Then when the client first had managed
# to get authenticated, traffic to the service_port is allowed through the firewall for the
# specified amount of time.
iptables -A PASSED -p tcp --dport $service_port -m recent --name AUTH2 --seconds $delay_interval --rcheck -j ACCEPT

# If the delay has passed (or the traffic is to another port or protocol than tcp to the
# service port), we remove the client from the AUTH2 list.
iptables -A PASSED -m recent --name AUTH2 --remove

# Remove the client from the AUTH2 list and accept the traffic that has passed the knocks
# assuming it is on the service port.
iptables -A PASSED -p tcp --dport $service_port -j ACCEPT

# Send the remaining traffic back to see if it matches the first knock
iptables -A PASSED -j GATE1


