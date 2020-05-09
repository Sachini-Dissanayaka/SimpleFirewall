import json

class Packet:

    def __init__(self, protocolType, sourceIpAdd, destinationIpAdd, sourcePort, destinationPort):
        if (protocolType == 'tcp'):
            self.protocolType = 'tcp'
        if (protocolType == 'udp'):
            self.protocolType = 'udp'
        self.sourceIpAdd = sourceIpAdd
        self.destinationIpAdd = destinationIpAdd
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort

class Firewall:

    def checkAcceptance(self, packet):
        filteringRules = self.readConfigFile()
        if (filteringRules != []):
            for rule in filteringRules:
                [isSatisfied, action] = self.isRuleSatisfied(rule, packet)
                if (isSatisfied):
                    if (action == 'permit'):
                        print('\nThe IP datagram is accepted.')
                    else:
                        print('\nThe IP datagram is discarded. Violate rule '+rule["ruleNo"])
                    break

    def isRuleSatisfied(self, rule, packet):
        sourceIpSatisfied = self.isIPddSatisfied(rule['sourceIpAdd'], packet.sourceIpAdd)
        destinationIpSatisfied = self.isIPddSatisfied(rule['destinationIpAdd'], packet.destinationIpAdd)
        sourcePortSatisfied = self.isPortSatisfied(rule['sourcePort'], packet.sourcePort)
        destinationPortSatisfied = self.isPortSatisfied(rule['destinationPort'], packet.destinationPort)
        typeSatisfied = self.isTypeSatisfied(rule['protocolType'], packet.protocolType)

        if (
                sourceIpSatisfied and destinationIpSatisfied and sourcePortSatisfied and destinationPortSatisfied and typeSatisfied):
            return [True, rule['action']]
        else:
            return [False, '']

    def isIPddSatisfied(self, ipAddress1, ipAddress2):
        if (ipAddress1 == '*'):
            return True
        elif (ipAddress1.count('*') == 0):
            if (ipAddress1 == ipAddress2):
                return True
            else:
                return False
        else:
            c = ipAddress1.count('*')
            ipAddress1 = ipAddress1.split('.')
            ipAddress2 = ipAddress2.split('.')
            isIdentical = ipAddress1[0] == ipAddress2[0]
            for i in range(4 - c):
                if (ipAddress1[i] != ipAddress1[i]):
                    isIdentical = False
                    break
            return isIdentical

    def isPortSatisfied(self, port1, port2):
        if (port1 == '*'):
            return True
        elif (port1[0] == '>'):
            if (port2 > int(port1[1:])):
                return True
            return False
        elif (port1[0] == '<'):
            if (port2 < int(port1[1:])):
                return True
            return False
        else:
            if (int(port1) == int(port2)):
                return True
            return False

    def isTypeSatisfied(self, type1, type2):
        if (type1 == '*'):
            return True
        elif (type1 == type2):
            return True
        else:
            return False

    def readConfigFile(self):
        try:
            with open('config.json', 'r') as configFile:
                data = json.load(configFile)
            return data['filteringRules']
        except:
            print('Error occured while retrieving data from the config file')
            return []





