#!/bin/bash
#(C) Kirils Solovjovs, 2018. SIPSA project
#
# If you have any trouble running this or any concerns,
# or if you would like your name listed in the research paper,
# please send the any comments to research@kirils.org
# Please include full output of this script where appropriate.

set -e

[ ! -r sipsa_test.c ] && echo source code not found in currect directory && exit 1

echo This is SIPSA research tool version 20180102.
echo
echo This tool will send less than 100 small packets to sipsa.kirils.org.
echo Various IP address data will be collected.
echo Expected runtime is less than 10 seconds, usually 1 second.
echo Root access will be required to craft some of the packets.
echo 
echo Press RETURN if you agree, or ^C to abort.
read


echo -n Verifying that all required tools are installed...

for tool in gcc cat grep cut head tail sed ip nc; do #sudo is excluded on purpose. the user can always run this as root.
	[ -z "$(which $tool | cat)" ] && echo && echo $tool is missing && exit 13
	echo -n $tool...
done
echo ALL GOOD.

echo -n Compiling test code...
gcc sipsa_test.c -o ./sipsa_test
echo done

echo -n Checking if test code runs on this machine...
[ -z "$(./sipsa_test |grep ^Usage)" ] && echo no && exit 10
echo yes

echo -n Detecting main network interface...
iface="$(cat /proc/net/route |grep -E 00000000.....+00000000|cut -d $'\t' -f 1|head -1)"
[ -z "$iface" ] && echo failed && exit 2
echo $iface

echo -n Getting IP address of the machine...
lip="$(ip addr show dev $iface | sed -E 's/^ +//'|grep ^inet\  | cut -d \  -f 2|head -1)"
[ -z "$lip" ] && echo failed && exit 3
echo $lip

netmask="$(echo $lip  | cut -d / -f 2)"
lip="$(echo $lip  | cut -d / -f 1)"

echo -n Calculating network address...
IFS=. read -r i1 i2 i3 i4 <<< "$lip"
IFS=. read -r m0 m1 m2 m3 m4 <<< $(for a in $(seq 1 32); do if [ $(((a - 1) % 8)) -eq 0 ]; then echo -n .; fi; if [ $a -le $netmask ]; then echo -n 1; else echo -n 0; fi; done)
na=$(printf "%d.%d.%d.%d" "$((i1 & (2#$m1)))" "$((i2 & (2#$m2)))" "$((i3 & (2#$m3)))" "$((i4 & (2#$m4)))")
echo $na

echo -n Getting broadcast address...
bc="$(ip addr show dev $iface | sed -E 's/^ +//'|grep ^inet\  | cut -d \  -f 4|head -1)"
[ -z "$bc" ] && echo failed && exit 3
echo $bc

echo -n Getting Real IP address...
rip="$(( sed -E 's/$/\r/' | nc 85.254.196.147 80 | tail -1 | grep '^[0-9]' | cat) << EOF
GET /detect_ip/ HTTP/1.0
Host: sipsa.kirils.org

EOF)"

[ -z "$rip" ] && echo failed && exit 4
echo $rip

echo -n Getting gateway address...
gw="$(ip route get 85.254.196.147 | sed -E 's/ +/ /g;s/ $//'|grep "$iface" | head -1 |cut -d \  -f 3| grep '^[0-9]' | cat)"
[ -z "$gw" ] && echo failed && exit 5
echo $gw

failmode=""
[ "$rip" != "$lip" ]	&& echo Real IP does not match the IP set on the interface. \
						&& echo This test is useless behind NAT, but proceeding anyway. In the name of SCIENCE\! \
						&& failmode="-nat"



[ "$UID" != "0" ] && sudo="sudo " || sudo=""
echo 
echo -n Running the tests as root...
$sudo echo -n

iplst=""

echo -n 1...
$sudo ./sipsa_test "$iface" "$lip" "$lip-$lip-native$failmode"
iplst="$iplst;$lip"

echo -n 2...
$sudo ./sipsa_test "$iface" "$gw" "$lip-$gw-gw$failmode"
iplst="$iplst;$gw"

echo -n 3...
$sudo ./sipsa_test "$iface" "$rip" "$lip-$rip-real$failmode"
iplst="$iplst;$rip"

echo -n 4...
$sudo ./sipsa_test "$iface" "$na" "$lip-$na-lan0$failmode"
iplst="$iplst;$tmpip"

echo -n 5...
$sudo ./sipsa_test "$iface" "$bc" "$lip-$bc-lanFF$failmode"
iplst="$iplst;$tmpip"
	
for ((i=1;i<=10;i++)); do
	echo -n 6.$i...
	tmpip="$(echo "$lip" |cut -d \. -f 1-3).$(($RANDOM % 256))"
	$sudo ./sipsa_test "$iface" "$tmpip" "$lip-$tmpip-lanRND$failmode"
	iplst="$iplst;$tmpip"
done


for ((i=1;i<=10;i++)); do #class A
	echo -n 7.$i...
	tmpip="$(($RANDOM % 126+1)).$(($RANDOM % 256)).$(($RANDOM % 256)).$(($RANDOM % 256))"
	$sudo ./sipsa_test "$iface" "$tmpip" "$lip-$tmpip-A$i$failmode"
	iplst="$iplst;$tmpip"
done

for ((i=1;i<=10;i++)); do #class B
	echo -n 8.$i...
	tmpip="$(($RANDOM % 40+128)).$(($RANDOM % 256)).$(($RANDOM % 256)).$(($RANDOM % 256))"
	$sudo ./sipsa_test "$iface" "$tmpip" "$lip-$tmpip-B$i$failmode"
	iplst="$iplst;$tmpip"
done

for ((i=1;i<=10;i++)); do #class C
	echo -n 9.$i...
	tmpip="$(($RANDOM % 30+193)).$(($RANDOM % 256)).$(($RANDOM % 256)).$(($RANDOM % 256))"
	$sudo ./sipsa_test "$iface" "$tmpip" "$lip-$tmpip-C$i$failmode"
	iplst="$iplst;$tmpip"
done

for ((i=1;i<=10;i++)); do #class D
	echo -n 10.$i...
	tmpip="$(($RANDOM % 16+224)).$(($RANDOM % 256)).$(($RANDOM % 256)).$(($RANDOM % 256))"
	$sudo ./sipsa_test "$iface" "$tmpip" "$lip-$tmpip-D$i$failmode"
	iplst="$iplst;$tmpip"
done

for ((i=1;i<=10;i++)); do #class E
	echo -n 11.$i...
	tmpip="$(($RANDOM % 14+240)).$(($RANDOM % 256)).$(($RANDOM % 256)).$(($RANDOM % 256))"
	$sudo ./sipsa_test "$iface" "$tmpip" "$lip-$tmpip-E$i$failmode"
	iplst="$iplst;$tmpip"
done

#private A
echo -n 12.1...
tmpip="10.$(($RANDOM % 256)).$(($RANDOM % 256)).$(($RANDOM % 256))"
$sudo ./sipsa_test "$iface" "$tmpip" "$lip-$tmpip-Ap$failmode"
iplst="$iplst;$tmpip"

#private B
echo -n 12.2...
tmpip="172.20.$(($RANDOM % 256)).$(($RANDOM % 256))"
$sudo ./sipsa_test "$iface" "$tmpip" "$lip-$tmpip-Bp$failmode"
iplst="$iplst;$tmpip"

#private C
echo -n 12.3...
tmpip="192.168.$(($RANDOM % 256)).$(($RANDOM % 256))"
$sudo ./sipsa_test "$iface" "$tmpip" "$lip-$tmpip-Cp$failmode"
iplst="$iplst;$tmpip"

echo done.
$sudo ./sipsa_test "$iface" "$lip" "REPORT:20180102:$lip-$iface$failmode$iplst"


echo Thank you for contributing to SIPSA research.
echo


