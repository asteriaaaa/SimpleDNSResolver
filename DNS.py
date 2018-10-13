from socket import *
import struct
import binascii
import time

serverport = 12358
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(('localhost', serverport))

querySocket = socket(AF_INET, SOCK_DGRAM)

cache = {}

class DNSQuery(object):
    def __init__(self, message):
        self.message = message
        (self.id, self.flags, self.quests, self.answers, self.author, self.addition) = struct.unpack('>HHHHHH',message[0:12])
        self.query = message[12:]
        self.name = self.query[:self.query.index(0o0)]
        self.type = self.query[self.query.index(0o0) + 1: self.query.index(0o0) + 3]
        self.clas = self.query[self.query.index(0o0) + 4: self.query.index(0o0) + 6]

    def sendQuery(self):
        querySocket.sendto(self.message, ("8.8.8.8", 53))

    def parse(self, number:int, length:int, cname=True) -> bytes:
        num = b''
        for i in range (length):
            num = bytes([number % 256]) + num
            number = number // 256
            return num


class DNSAnswer(object):
    def __init__(self, message, id):
        self.rawMessage = message
        self.id = b''
        self.answerRR = int(binascii.b2a_hex(self.rawMessage[6:8]).decode(), 16)
        tt = 400
        for i in range (2):
            self.id = bytes([id % 256]) + self.id
            id = id // 256
        self.aftermessage = self.id + self.rawMessage[2:]

    def parseTTL(self): 
        goodmsg = self.rawMessage[12:] #Start after the query name
        index = goodmsg.index(0o0) + 4 + 12
        self.ttl = []
        self.ttlpos = []
        for i in range (self.answerRR): #According to the pattern...
            index += 6
            self.ttl.append(int (binascii.b2a_hex(self.rawMessage[index+1:index+5]).decode(), 16))
            self.ttlpos.append(index + 1)
            lenth = int (binascii.b2a_hex(self.rawMessage[index + 5: index + 7]).decode(), 16)
            index += 6 + lenth
        return self.ttl

    def modifyTTL(self, val):
        i = 0
        for t in self.ttlpos:
            if self.ttl[i] - val < 0:
                return False
            now = hex(self.ttl[i] - val)
            now = now.split('x')[1]
            while len(now) != 8:
                now = '0' + now
            update = bytes().fromhex(now)
            self.aftermessage = self.aftermessage[:t] + update + self.aftermessage[t+4:]
            i += 1
        return True


if __name__ == "__main__":
    while True:
        message = None
        query = serverSocket.recvfrom(2048)
        if query:
            qr = query[0]
            dqr = DNSQuery(qr)
            if cache.__contains__((dqr.name, dqr.type, dqr.clas)):
                dans = DNSAnswer(cache[(dqr.name, dqr.type, dqr.clas)][0], dqr.id)
                timecon = time.time()
                ttl = dans.parseTTL()
                if dans.modifyTTL(int(timecon - cache[(dqr.name, dqr.type, dqr.clas)][1])):
                    message = dans.aftermessage
                else:
                    cache.pop((dqr.name, dqr.type, dqr.clas))
                    dqr.sendQuery()
                    message, addr = querySocket.recvfrom(2048)
            else:
                dqr.sendQuery()
                message, addr = querySocket.recvfrom(2048)
            if (message):
                if not cache.__contains__(message):
                    cache[(dqr.name, dqr.type, dqr.clas)] = (message, time.time())
                serverSocket.sendto(message, query[1])

