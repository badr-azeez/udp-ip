import pyshark, netifaces

print('|#| udp-ip |#|\n|#| By: Badr Azeez |#| ')

srcips = []  # stored packet
interface = netifaces.gateways()['default'][netifaces.AF_INET][1]  # interface
dest = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']  # ip address this lab
gws = netifaces.gateways()
gw = gws['default'][2][0]
try:
    # get packet
    cap = pyshark.LiveCapture('wlan0', bpf_filter='udp')
    for packet in cap.sniff_continuously(packet_count=15):
        ip = packet['ip'].src
        srcips.append(ip)
    cap.close()
except PermissionError:
    exit('run as root')

if len(srcips) > 0:
    for ip in set(srcips):
        if ip != dest and ip != gw:
            print('ip:', ip)
else:
    exit('Not Found udp packet')
