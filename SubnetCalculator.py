import ipaddress

def main():
    print('To close program type "exit" anywhere')
    while True:
        ip = getIP()
        ipType = checkIP(ip)
        sub = getSub(ipType)
        sub = list(map(int, sub))
        subBinary = getBinary(sub)
        wildcard = getWildcard(sub)
        hosts = getHosts(subBinary)
        netAddr = getNetworkAddress(ip,sub)
        broadcast = getBroadcast(ip,sub)

        wildcard = f"{wildcard[0]}.{wildcard[1]}.{wildcard[2]}.{wildcard[3]}"
        display(netAddr,subBinary,broadcast,wildcard,hosts)

def getIP():
    while True:
        ip = input("IP Address: ")
        checkExit(ip)

        if '.' not in ip:
            print("Not valid ip address!")
            continue
        elif ip == "127.0.0.1":
            print("Cannot be the loopback address!")
            continue

        ip = ip.split(".")
        ip = list(map(int, ip))

        if len(ip) != 4:
            print("Needs to have 4 octets!")
            continue
        elif ip[0] == 0:
            print("First octect cannot be 0!")
            continue
        elif ip[0] < 1 or ip[0] > 223:
            print("IP address has to be class A,B or C!")
            continue
        else:
            break

    return ip

def checkIP(ip):
    if ip[0] > 0 and ip[0] < 128:
        ipType = "A"
    elif ip[0] > 127 and ip[0] < 192:
        ipType = "B"
    else:
        ipType = "C"

    return ipType

def getSub(ipType):
    while True:
        sub = input("Subnet Mask: ")
        checkExit(sub)

        if "." not in sub:
            print("Not valid subnet mask!")
            continue

        sub = sub.split(".")
        sub = list(map(int, sub))

        if len(sub) != 4:
            print("Subnet mask needs 4 octets!")
            continue
        elif sub[0] != 255:
            print("First octet must be 255!")
            continue
        elif sub[3] == 255:
            print("Last octet cannot be 255!")
            continue

        subValid = [255,254,252,248,240,224,192,128,0]

        if ipType == "A" and sub[0] == 255:
            if sub[1] == 255 and sub[2] == 255 and sub[3] in subValid:
                break
            elif sub[1] == 255 and sub[2] in subValid and sub[3] == 0:
                break
            elif sub[1] in subValid and sub[2] == 0 and sub[3] == 0:
                break
            else:
                print("Not valid subnet mask!")
                continue
        elif ipType == "B" and sub[0] == 255 and sub[1] == 255:
            if sub[2] == 255 and sub[3] in subValid:
                break
            elif sub[2] in subValid and sub[3] == 0:
                break
            else:
                print("Not valid subnet mask!")
                continue
        elif ipType == "C" and sub[0] == 255 and sub[1] == 255 and sub[2] == 255 and sub[3] in subValid:
            break
        else:
            print("Not valid subnet mask!")
            continue

    return sub

def getWildcard(sub):
    wild1 = 255 - sub[0]
    wild2 = 255 - sub[1]
    wild3 = 255 - sub[2]
    wild4 = 255 - sub[3]
    wildcard = [wild1,wild2,wild3,wild4]
    wildcard = list(map(int, wildcard))
    return wildcard

def getBinary(x):
    bin1 = bin(x[0])[2:].zfill(8)
    bin2 = bin(x[1])[2:].zfill(8)
    bin3 = bin(x[2])[2:].zfill(8)
    bin4 = bin(x[3])[2:].zfill(8)
    binary = f"{bin1}.{bin2}.{bin3}.{bin4}"
    return binary

def getHosts(subBinary):
    hostBits = subBinary.count("0")
    hosts = (2 ** hostBits) - 2
    return hosts

def getNetworkAddress(ip,sub):
    ipBin = getBinary(ip).replace('.','')
    subBin = getBinary(sub).replace('.','')
    netAddrBin = bin(int(ipBin,2) & int(subBin,2))[2:].zfill(32)
    netAddr = binaryToIP(netAddrBin)
    return netAddr

def binaryToIP(x):
    ip = str(ipaddress.ip_address(int(x,2)))
    return ip

def getBroadcast(ip,sub):
    hostBits = getBinary(sub).count("0")
    ipBin = getBinary(ip).replace('.','')
    ipBin = ipBin[:-hostBits]
    broadcastBin = ipBin + ("1" * hostBits)
    broadcast = binaryToIP(broadcastBin)
    return broadcast

def display(netAddr,subBinary,broadcast,wildcard,hosts):
    print()
    print("Network Address: " + str(netAddr))
    print("Subnet Mask (Binary): " + str(subBinary))
    print("Broadcast Address: " + str(broadcast))
    print("Wildcard Mask: " + str(wildcard))
    print("Number of usable hosts: " + str("{:,}".format(hosts)))
    print()

def checkExit(x):
    if x == "exit":
        quit()

main()
