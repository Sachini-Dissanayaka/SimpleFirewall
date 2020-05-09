from firewall import *
import json

option = int(input("Enter the number(Inbound>>1 and Outbound>>2):"))
if option == 1:
    file = "inbound.json"
elif option == 2:
    file = "outbound.json"
else:
    print("Enter a valid number")
    option = int(input("Enter the number(Inbound>>1 and Outbound>>2):"))


with open("inbound.json", "r") as json_file:
    data = json.load(json_file)
    c=0
    for user in data:
        if("tcp" in user["_source"]["layers"]):
            sourceIpAdd = user["_source"]["layers"]["ip"]["ip.src"]
            destinationIpAdd = user["_source"]["layers"]["ip"]["ip.dst"]
            sourcePort = int(user["_source"]["layers"]["tcp"]["tcp.srcport"])
            destinationPort = int(user["_source"]["layers"]["tcp"]["tcp.dstport"])
            protocolType = "tcp"
            packet = Packet(protocolType, sourceIpAdd, destinationIpAdd, sourcePort, destinationPort)
            firewall = Firewall()
            firewall.checkAcceptance(packet)
        elif ("udp" in user["_source"]["layers"]):
            sourceIpAdd = user["_source"]["layers"]["ip"]["ip.src"]
            destinationIpAdd = user["_source"]["layers"]["ip"]["ip.dst"]
            sourcePort = int(user["_source"]["layers"]["udp"]["udp.srcport"])
            destinationPort = int(user["_source"]["layers"]["udp"]["udp.dstport"])
            protocolType = "udp"
            packet = Packet(protocolType, sourceIpAdd, destinationIpAdd, sourcePort, destinationPort)
            firewall = Firewall()
            firewall.checkAcceptance(packet)

