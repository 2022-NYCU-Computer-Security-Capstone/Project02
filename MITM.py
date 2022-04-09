from scapy.all import *

def getGatewayIP():
    result = conf.route.route("0.0.0.0")[2]
    return result

if "__main__" == __name__:
    print("Gateway IP: ", getGatewayIP())
