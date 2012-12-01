from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ClientEndpoint

from txsocksx.client import SOCKS5ClientEndpoint

class GETSlash(Protocol):
    def connectionMade(self):
        self.transport.write("GET / HTTP/1.1\n\r\n\r")

    def buildProtocol(self):
        return self

    def dataReceived(self, data):
        print "Got this as a response"
        print data

class GETSlashFactory(Factory):
    def buildProtocol(self, addr):
        print "Building protocol towards"
        return GETSlash()

socks_addr = '127.0.0.1'
socks_port = 9050
TCPPoint = TCP4ClientEndpoint(reactor, socks_addr, socks_port)

dst_addr = 'checkip.dyndns.com'
dst_port = 80
SOCKSPoint = SOCKS5ClientEndpoint(dst_addr,
            dst_port, TCPPoint)

d = SOCKSPoint.connect(GETSlashFactory())
@d.addErrback
def _gotError(error):
    print "Error in connection"
    reactor.stop()

reactor.run()

