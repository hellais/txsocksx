from twisted.internet import reactor, defer
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ClientEndpoint

from txsocksx.client import SOCKS5ClientEndpoint

class SScan(Protocol):
    addr = '127.0.0.1:9050'
    buf = ""
    def connectionMade(self):
        self.transport.write("GET / HTTP/1.1\r\n\r\n")

    def buildProtocol(self):
        return self

    def dataReceived(self, data):
        print "works: %s" % self.addr
        for line in data.split('\r\n'):
            if 'Current IP Address' in line:
                exit_ip = line.split(":")[1].replace("</body></html>", "").strip()
                print "exit ip: %s" % exit_ip
        self.transport.loseConnection()

class SScanFactory(Factory):
    def __init__(self, addr):
        self.addr = addr

    def buildProtocol(self, addr):
        print "Building protocol towards"
        p = SScan()
        p.addr = self.addr
        return p

proxies = ['127.0.0.1:9050', '127.0.0.1:9050']

for addr in proxies:
    dl = []
    socks_addr, socks_port = addr.split(':')
    socks_port = int(socks_port)

    TCPPoint = TCP4ClientEndpoint(reactor, socks_addr, socks_port)

    dst_addr = 'checkip.dyndns.com'
    dst_port = 80
    SOCKSPoint = SOCKS5ClientEndpoint(dst_addr,
                dst_port, TCPPoint)

    f = SScanFactory(addr)
    d = SOCKSPoint.connect(f)

    @d.addErrback
    def _gotError(error):
        print "Error in connection to %s" % addr

reactor.run()

