import scapy.all as scapy

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

if "__main__" == __name__:
    gw = getGatewayIP()
    print("Gateway IP: ", gw)

    devices = scan(gw + "/24")

    print("Avaliable devices")
    print("---------------------------")
    print("IP                 MAC     ")
    print("---------------------------")


    for item in devices:
        print(item["ip"], item["mac"], sep = '\t')
