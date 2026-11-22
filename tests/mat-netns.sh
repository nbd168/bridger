#!/bin/sh
# SPDX-License-Identifier: GPL-2.0+
#
# Client bridge test in network namespaces. No radio: a veth pair stands for
# the station, and tc filters on its far end apply the rule of an AP: accept
# only the station's source address, deliver only to the station's address
# or to a group address.
#
# Usage: mat-netns.sh <bridger binary> <log dir> [ld library path]
# Needs root, ubusd, dnsmasq, busybox (udhcpc, arping) and ip/tc.

BRIDGER=$1
LOGS=$2
LIBS=$3

if [ -z "$BRIDGER" ] || [ -z "$LOGS" ]; then
	echo "Usage: $0 <bridger binary> <log dir> [ld library path]" >&2
	exit 2
fi

if [ -z "$MAT_TEST_INNER" ]; then
	mkdir -p "$LOGS"
	exec sudo -n env MAT_TEST_INNER=1 unshare -m -n "$0" "$@"
fi

NET=192.168.77
NET6=fd77
PD=fd99
STA_MAC=02:aa:00:00:00:01
STA2_MAC=02:aa:00:00:00:02
FAILED=0
PASSED=0
HAVE_SCAPY=$(python3 -c 'import scapy.all; print(1)' 2>/dev/null)

pass() {
	PASSED=$((PASSED + 1))
	echo "PASS: $1"
}

fail() {
	FAILED=$((FAILED + 1))
	echo "FAIL: $1"
}

check() {
	local name=$1
	shift

	if "$@" >> "$LOGS/check.log" 2>&1; then
		pass "$name"
	else
		fail "$name"
	fi
}

check_fail() {
	local name=$1
	shift

	if "$@" >> "$LOGS/check.log" 2>&1; then
		fail "$name"
	else
		pass "$name"
	fi
}

ns() {
	local name=$1
	shift

	ip netns exec "$name" "$@"
}

status() {
	ubus call bridger mat_status
}

host_ip() {
	ns "$1" ip -4 -o addr show dev eth0 | sed -n 's/.* inet \([0-9.]*\)\/.*/\1/p'
}

host_mac() {
	ns "$1" cat /sys/class/net/eth0/address
}

dhcp_start() {
	ns "$1" busybox udhcpc -i eth0 -n -q -f -t 5 -T 1 -s "$LOGS/udhcpc.script" \
		>> "$LOGS/udhcpc-$1.log" 2>&1
}

# The clsact qdisc counts the frames of both directions: 200 echo requests
# leave through the port, and the answers only enter it without a flow.
port_packets() {
	tc -s qdisc show dev cb0 clsact | sed -n 's/.* \([0-9]*\) pkt.*/\1/p'
}

rx_down() {
	status | sed -n 's/.*"rx_down": \([0-9]*\).*/\1/p' | head -n 1
}

tx_up() {
	status | sed -n 's/.*"tx_up": \([0-9]*\).*/\1/p' | head -n 1
}

dhcp6_start() {
	ns "$1" busybox udhcpc6 -i eth0 -n -q -f -t 5 -T 1 -s "$LOGS/udhcpc6.script" \
		>> "$LOGS/udhcpc6-$1.log" 2>&1
}

host_ip6() {
	ns "$1" ip -6 -o addr show dev eth0 scope global | grep -v tentative | \
		sed -n "s/.* inet6 \($NET6:[0-9a-f:]*ff:fe[0-9a-f:]*\)\/.*/\1/p" | head -n 1
}

host_ll() {
	ns "$1" ip -6 -o addr show dev eth0 scope link | \
		sed -n 's/.* inet6 \([0-9a-f:]*\)\/.*/\1/p' | head -n 1
}

slaac_wait() {
	local i

	for i in $(seq 15); do
		[ -n "$(host_ip6 "$1")" ] && return 0
		sleep 1
	done

	return 1
}

# The rule of an AP for one station. An AP also sends the group frames of a
# station back to it.
ap_filters() {
	local dev=$1
	local mac=$2
	local group=01:00:00:00:00:00/01:00:00:00:00:00

	ns up tc qdisc add dev $dev clsact
	ns up tc filter add dev $dev ingress pref 1 flower src_mac $mac \
		dst_mac $group action mirred egress mirror dev $dev
	ns up tc filter add dev $dev ingress pref 2 flower src_mac $mac action pass
	ns up tc filter add dev $dev ingress pref 3 matchall action drop
	ns up tc filter add dev $dev egress pref 1 flower dst_mac $mac action pass
	ns up tc filter add dev $dev egress pref 2 flower dst_mac $group action pass
	ns up tc filter add dev $dev egress pref 3 matchall action drop
}

cleanup() {
	kill $(cat "$LOGS/bridger.pid" "$LOGS/ubusd.pid" "$LOGS/dnsmasq.pid" \
		   "$LOGS/tcpdump.pid" 2>/dev/null) 2>/dev/null
}

trap cleanup EXIT

# A mount namespace does not hide writes: ip netns and ubusd write below /run,
# so the test gets a /run of its own.
mount --make-rprivate /
mount -t tmpfs tmpfs /run
mkdir -p /run/ubus /run/netns
mount -t sysfs sysfs /sys
mount -t bpf bpf /sys/fs/bpf

rm -f "$LOGS"/*.log
cat > "$LOGS/udhcpc.script" <<'EOF'
#!/bin/sh
case "$1" in
bound|renew)
	ip -4 addr flush dev "$interface"
	ip addr add "$ip/${mask:-24}" dev "$interface"
	;;
deconfig)
	ip -4 addr flush dev "$interface"
	ip link set "$interface" up
	;;
esac
EOF
cat > "$LOGS/udhcpc6.script" <<'EOF'
#!/bin/sh
[ "$1" = bound ] && ip -6 addr add "$ipv6/128" dev "$interface"
exit 0
EOF
chmod +x "$LOGS/udhcpc.script" "$LOGS/udhcpc6.script"

ubusd > "$LOGS/ubusd.log" 2>&1 &
echo $! > "$LOGS/ubusd.pid"

ip link set lo up
for n in up x h1 h2; do
	ip netns add $n
	ip -n $n link set lo up
done

ip link add br-lan type bridge
ip link set br-lan up
for i in 1 2; do
	ip link add lan$i type veth peer name eth0 netns h$i
	ip link set lan$i master br-lan up
	ip -n h$i link set eth0 up
done

ip link add sta0 address $STA_MAC type veth peer name ap0 netns up
ip link set sta0 up

ip -n up link add br-up type bridge
ip -n up link set br-up up
ip -n up link set ap0 master br-up up
ip -n up link add xp type veth peer name eth0 netns x
ip -n up link set xp master br-up up
ip -n up addr add $NET.1/24 dev br-up
ip -n x link set eth0 up
ip -n x addr add $NET.2/24 dev eth0

ip -n up addr add $NET6::1/64 dev br-up nodad
ip -n x addr add $NET6::2/64 dev eth0 nodad

ap_filters ap0 $STA_MAC

ns up dnsmasq --keep-in-foreground --port=0 --interface=br-up --bind-interfaces \
	--dhcp-range=$NET.100,$NET.150,120 --dhcp-leasefile="$LOGS/leases.log" \
	--enable-ra --dhcp-range=$NET6::100,$NET6::1ff,slaac,64,120 \
	--log-dhcp --log-facility="$LOGS/dnsmasq.log" --conf-file=/dev/null &
echo $! > "$LOGS/dnsmasq.pid"

ns h2 tcpdump -n -e -l -i eth0 ether src $STA_MAC > "$LOGS/echo.log" 2>/dev/null &
echo $! > "$LOGS/tcpdump.pid"

LD_LIBRARY_PATH=$LIBS "$BRIDGER" -d > "$LOGS/bridger.log" 2>&1 &
echo $! > "$LOGS/bridger.pid"

check "bridger registers on ubus" ubus -t 10 wait_for bridger
check "client bridge configuration" ubus call bridger set_device_config \
	'{"name":"sta0","client_bridge":{"port":"cb0","bridge":"br-lan"}}'
sleep 1
check "proxy port is a bridge member" test -d /sys/class/net/br-lan/brif/cb0
check "instance is active" sh -c "ubus call bridger mat_status | grep -q '\"active\": true'"

check "h1 gets a lease" dhcp_start h1
check "h2 gets a lease" dhcp_start h2
H1=$(host_ip h1)
H2=$(host_ip h2)
echo "h1=$H1 h2=$H2" >> "$LOGS/check.log"

check "server saw the MAC of h1 as chaddr" grep -qi "DHCPACK.*$(host_mac h1)" "$LOGS/dnsmasq.log"
check "server saw the MAC of h2 as chaddr" grep -qi "DHCPACK.*$(host_mac h2)" "$LOGS/dnsmasq.log"
check "binding of h1 from DHCP" sh -c "ubus call bridger mat_status | grep -A3 '\"$H1\"' | grep -q dhcp"

check "h1 reaches the upstream router" ns h1 ping -c 2 -W 2 $NET.1
check "h2 reaches the upstream host" ns h2 ping -c 2 -W 2 $NET.2
check "upstream host reaches h1" ns x ping -c 2 -W 2 "$H1"
check "h1 reaches h2 on the LAN" ns h1 ping -c 2 -W 2 "$H2"
check "upstream sees the station MAC for h1" sh -c \
	"ip netns exec x ip neigh show $H1 | grep -qi $STA_MAC"

check "the device's own stack gets a lease on the bridge" busybox udhcpc -i br-lan \
	-n -q -f -t 5 -T 1 -s "$LOGS/udhcpc.script"
check "the device's own stack reaches the upstream host" ping -c 2 -W 2 $NET.2
check "upstream host reaches the device's own stack" ns x ping -c 2 -W 2 \
	"$(ip -4 -o addr show dev br-lan | sed -n 's/.* inet \([0-9.]*\)\/.*/\1/p')"

ip -n h2 addr add $NET.50/24 dev eth0
ns x ip neigh replace $NET.50 lladdr $STA_MAC dev eth0
check "frame to an unbound address waits for the resolution" ns x ping -c 1 -W 2 $NET.50
check "binding from the resolution" sh -c "ubus call bridger mat_status | grep -q '\"$NET.50\"'"

check_fail "address probe from the LAN finds the upstream owner" \
	ns h1 busybox arping -D -c 2 -w 3 -I eth0 $NET.2
check "address probe from the LAN for a free address" \
	ns h1 busybox arping -D -c 2 -w 3 -I eth0 $NET.9

ns h1 ping -c 20 -i 0.01 -W 2 -q $NET.2 >> "$LOGS/check.log" 2>&1
sleep 2
PORT_PKTS=$(port_packets)
TX_UP=$(tx_up)
ns h1 ping -c 200 -i 0.01 -W 2 -q $NET.2 >> "$LOGS/check.log" 2>&1
PORT_PKTS=$(($(port_packets) - PORT_PKTS))
TX_UP=$(($(tx_up) - TX_UP))
echo "frames on the proxy port during the flood: $PORT_PKTS" >> "$LOGS/check.log"
echo "frames sent upstream by the daemon during the flood: $TX_UP" >> "$LOGS/check.log"
check "frames from the station bypass the proxy port" test "$PORT_PKTS" -lt 300
check "data frames stay in the kernel" test "$TX_UP" -lt 20

if [ -n "$HAVE_SCAPY" ]; then
	RX_DOWN=$(rx_down)
	ns h1 python3 - >> "$LOGS/check.log" 2>&1 <<'EOF'
from scapy.all import *

sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / Dot1AD(vlan=4095) /
      ARP(op=2, psrc="192.168.77.2", pdst="192.168.77.1"),
      iface="eth0", count=40, verbose=False)
EOF
	sleep 1
	RX_DOWN=$(($(rx_down) - RX_DOWN))
	echo "frames taken as from the station: $RX_DOWN" >> "$LOGS/check.log"
	check "a LAN host cannot mark a frame as coming from the station" \
		test "$RX_DOWN" -lt 40
else
	echo "SKIP: forged direction tag (no scapy)"
fi

for h in h1 h2; do
	ns $h sysctl -q -w net.ipv6.conf.eth0.enhanced_dad=0
	ip -n $h link set eth0 down
	ip -n $h link set eth0 up
done
check "h1 gets an address from the router advertisement" slaac_wait h1
check "h2 gets an address from the router advertisement" slaac_wait h2
H1_6=$(host_ip6 h1)
H2_6=$(host_ip6 h2)
echo "h1=$H1_6 h2=$H2_6" >> "$LOGS/check.log"

check "h1 reaches the upstream router over IPv6" ns h1 ping -6 -c 2 -W 2 $NET6::1
check "h2 reaches the upstream host over IPv6" ns h2 ping -6 -c 2 -W 2 $NET6::2
check "upstream host reaches h1 over IPv6" ns x ping -6 -c 2 -W 2 "$H1_6"
check "h1 reaches h2 on the LAN over IPv6" ns h1 ping -6 -c 2 -W 2 "$H2_6"
check "upstream sees the station MAC for the IPv6 address of h1" sh -c \
	"ip netns exec x ip -6 neigh show $H1_6 | grep -qi $STA_MAC"

ip -n h2 addr add $NET6::2/64 dev eth0
sleep 3
check "duplicate address detection finds the upstream owner" sh -c \
	"ip -n h2 -6 addr show dev eth0 | grep '$NET6::2/' | grep -q dadfailed"
ip -n h2 addr del $NET6::2/64 dev eth0

ip -n h2 addr add $NET6::50/64 dev eth0
sleep 3
check_fail "duplicate address detection accepts a free address" sh -c \
	"ip -n h2 -6 addr show dev eth0 | grep '$NET6::50/' | grep -q 'dadfailed\|tentative'"
ubus call bridger mat_status > "$LOGS/status-v6.log"
ns x ip -6 neigh replace $NET6::50 lladdr $STA_MAC dev eth0
check "IPv6 frame to a static address reaches the host" ns x ping -6 -c 1 -W 2 $NET6::50

check "h1 gets a DHCPv6 lease" dhcp6_start h1
H1_D6=$(ns h1 ip -6 -o addr show dev eth0 | sed -n 's/.* inet6 \([0-9a-f:]*\)\/128.*/\1/p')
echo "h1 dhcpv6=$H1_D6" >> "$LOGS/check.log"
check "binding of h1 from DHCPv6" sh -c \
	"ubus call bridger mat_status | grep -A3 '\"$H1_D6\"' | grep -q dhcp"
check "upstream host reaches the DHCPv6 address of h1" ns x ping -6 -c 2 -W 2 "$H1_D6"

if [ -n "$HAVE_SCAPY" ]; then
	ns x python3 - "$(ns x cat /sys/class/net/eth0/address)" $STA_MAC \
		"$(host_ll x)" "$(host_ll h1)" $PD:: >> "$LOGS/check.log" 2>&1 <<'EOF'
import sys
from scapy.all import *

src_mac, dst_mac, src, dst, prefix = sys.argv[1:]
sendp(Ether(src=src_mac, dst=dst_mac) / IPv6(src=src, dst=dst) /
      UDP(sport=547, dport=546) / DHCP6_Reply(trid=1) /
      DHCP6OptIA_PD(iaid=1, T1=60, T2=90, iapdopt=[
          DHCP6OptIAPrefix(preflft=120, validlft=120, plen=56, prefix=prefix)]),
      iface="eth0", verbose=False)
EOF
	sleep 1
	check "delegated prefix from a DHCPv6 Reply" sh -c \
		"ubus call bridger mat_status | grep -q '\"$PD::/56\"'"
	ip -n h1 addr add $PD::1/64 dev eth0 nodad
	ip -n x -6 route add $PD::/56 dev eth0
	ns x ip -6 neigh replace $PD::1 lladdr $STA_MAC dev eth0
	check "upstream host reaches an address in the delegated prefix" \
		ns x ping -6 -c 2 -W 2 $PD::1
	check_fail "an address in the delegated prefix needs no binding" sh -c \
		"ubus call bridger mat_status | grep -q '\"$PD::1\"'"
else
	echo "SKIP: delegated prefix (no scapy)"
fi

kill $(cat "$LOGS/tcpdump.pid")
sleep 1
check_fail "no group frame of the station came back from the AP" test -s "$LOGS/echo.log"

ip link add sta1 address $STA2_MAC type veth peer name ap1 netns up
ip link set sta1 up
ip -n up link set ap1 master br-up up
ap_filters ap1 $STA2_MAC
check "second client bridge on the same LAN" ubus call bridger set_device_config \
	'{"name":"sta1","client_bridge":{"port":"cb1","bridge":"br-lan"}}'
sleep 7
ubus call bridger mat_status > "$LOGS/status-loop.log"
check "one of two client bridges on one LAN stops" sh -c \
	"test \$(grep -c '\"loop\": true' '$LOGS/status-loop.log') = 1"
check "the first client bridge keeps running" sh -c \
	"grep -A6 '\"sta0\"' '$LOGS/status-loop.log' | grep -q '\"loop\": false'"
check "h1 reaches the upstream host beside a stopped client bridge" \
	ns h1 ping -c 2 -W 2 $NET.2
ubus call bridger set_device_config '{"name":"sta1","client_bridge":{}}'
ip link del sta1

ip link del cb0
sleep 7
check "the instance comes back after the loss of its proxy port" \
	test -d /sys/class/net/br-lan/brif/cb0
check "h1 reaches the upstream host through the new proxy port" \
	ns h1 ping -c 3 -W 2 $NET.2

ip -n up link set ap0 down
sleep 1
ip -n up link set ap0 up
sleep 2
check_fail "bindings are gone after the station lost its link" sh -c \
	"ubus call bridger mat_status | grep -q '\"$H1\"'"
check "h1 reaches the upstream host after the link came back" \
	ns h1 ping -c 3 -W 2 $NET.2

check "switch to dhcp_mode chaddr" ubus call bridger set_device_config \
	'{"name":"sta0","client_bridge":{"port":"cb0","bridge":"br-lan","dhcp_mode":"chaddr"}}'
ip -n h2 addr flush dev eth0
: > "$LOGS/dnsmasq-before-chaddr.log"
cp "$LOGS/dnsmasq.log" "$LOGS/dnsmasq-before-chaddr.log"
check "h2 gets a lease in chaddr mode" dhcp_start h2
check "server saw the station MAC as chaddr" sh -c \
	"tail -n +\$((\$(wc -l < '$LOGS/dnsmasq-before-chaddr.log') + 1)) '$LOGS/dnsmasq.log' | grep -qi 'DHCPACK.*$STA_MAC'"
check "h2 reaches the upstream host in chaddr mode" ns h2 ping -c 2 -W 2 $NET.2

ns up tc -s filter show dev ap0 ingress > "$LOGS/ap-ingress.log"
ns up tc -s filter show dev ap0 egress > "$LOGS/ap-egress.log"
check "no frame left the station with a foreign source address" sh -c \
	"sed -n '/pref 3 /,\$p' '$LOGS/ap-ingress.log' | grep -q 'Sent 0 bytes'"
check "upstream sent no unicast frame to a LAN host address" sh -c \
	"sed -n '/pref 3 /,\$p' '$LOGS/ap-egress.log' | grep -q 'Sent 0 bytes'"

status > "$LOGS/status.log"
kill $(cat "$LOGS/bridger.pid")
sleep 1
check_fail "proxy port is gone after the daemon exits" test -d /sys/class/net/cb0

echo "passed=$PASSED failed=$FAILED"
[ "$FAILED" = 0 ]
