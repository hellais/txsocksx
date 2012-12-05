import struct

from twisted.internet import protocol, defer, interfaces
from twisted.python import failure
from zope.interface import implements

from txsocksx import constants as c
import txsocksx.errors as e

from txsocksx import auth

from txsocksx.parser import SOCKSGrammar

def shortToBytes(i):
    return chr(i >> 8) + chr(i & 0xff)

class SOCKS5ClientTransport(object):
    def __init__(self, wrappedClient):
        self.wrappedClient = wrappedClient
        self.transport = self.wrappedClient.transport

    def __getattr__(self, attr):
        return getattr(self.transport, attr)

class SOCKS5Client(protocol.Protocol):
    implements(interfaces.ITransport)

    otherProtocol = None
    debug = False

    def __init__(self):
        self._state = 'ServerVersionMethod'

    def connectionMade(self):
        self.writeVersionMethod()

    def writeVersionMethod(self):
        """
        This creates:
            ver octet:nmethods octet{2, 255}:methods
        """
        supported_methods = [m.method for m in self.factory.authMethods]

        message = struct.pack('!BB', c.VER_SOCKS5,
                    len(supported_methods))
        message += ''.join(supported_methods)

        self.transport.write(message)

    def writeRequest(self, result, cmd=c.CMD_CONNECT):
        """
        This creates:
            clientRequestMessage =
                ver cmd rsv SOCKSAddress port
        """
        # XXX-Security audit makeGrammar
        message = SOCKSGrammar(self.factory.host)
        req = struct.pack('!BBB', c.VER_SOCKS5, cmd, 0)
        self.transport.write(
                req + \
                    message.hostToSOCKSAddress() + \
                        shortToBytes(self.factory.port)
        )
        self.log("writeRequest %s" % (repr(req)))
        self._state = 'ServerReply'

    def readServerVersionMethod(self, message):
        self.log("readServerVersionMethod")
        ver, method = message.serverVersionMethod()
        if method not in self.factory.authMethods:
            raise e.MethodsNotAcceptedError(
                    'no method proprosed was accepted',
                        self.factory.authMethods, method)
        else:
            auth_method = method()
            d = defer.maybeDeferred(auth_method.negotiate, self)
            d.addCallback(self.writeRequest)

    def readServerReply(self, message):
        status, address, port = message.serverReply()
        self.log("readServerReply %s %s %s" % (status, address, port))
        if status != 0:
            raise status

        self._state = 'ProxyData'
        self.factory.proxyConnectionEstablished(self)

    def readProxyData(self, data):
        # There really is no reason for this to get called; we shouldn't be in
        # raw mode until after SOCKS negotiation finishes.
        assert self.otherProtocol is not None
        self.otherProtocol.dataReceived(data)

    def dataReceived(self, data):
        self.log("Got some data %s" % repr(data))
        if self._state == 'ProxyData':
            self.readProxyData(data)
            return

        # XXX-Security audit makeGrammar
        message = SOCKSGrammar(data)

        current_state_method = getattr(self, 'read' + self._state)
        d = defer.maybeDeferred(current_state_method,
                    message)

    def proxyEstablished(self, other):
        self.otherProtocol = other
        other.makeConnection(SOCKS5ClientTransport(self))

    def connectionLost(self, reason):
        if self.otherProtocol:
            self.log("Connection Lost with other protocol")
            self.otherProtocol.connectionLost(reason)
        else:
            self.log("Connection Lost with no protocol")
            self.factory.proxyConnectionFailed(
                failure.Failure(e.ConnectionLostEarly()))

    def log(self, msg):
        if self.debug:
            print msg

class SOCKS5ClientFactory(protocol.ClientFactory):
    protocol = SOCKS5Client

    def __init__(self, host, port, proxiedFactory, authMethods):
        self.host = host
        self.port = port
        self.proxiedFactory = proxiedFactory
        self.authMethods = authMethods
        self.deferred = defer.Deferred()

    def proxyConnectionFailed(self, reason):
        self.deferred.errback(reason)

    def clientConnectionFailed(self, connector, reason):
        print "Failed because of %s" % reason
        self.proxyConnectionFailed(reason)

    def proxyConnectionEstablished(self, proxyProtocol):
        proto = self.proxiedFactory.buildProtocol(
            proxyProtocol.transport.getPeer())
        # XXX: handle the case of `proto is None`
        proxyProtocol.proxyEstablished(proto)
        self.deferred.callback(proto)

class SOCKS5ClientEndpoint(object):
    implements(interfaces.IStreamClientEndpoint)

    def __init__(self, host, port, proxyEndpoint, authMethods=(auth.Anonymous,)):
        self.host = host
        self.port = port
        self.proxyEndpoint = proxyEndpoint
        self.authMethods = authMethods

    def connect(self, fac):
        proxyFac = SOCKS5ClientFactory(self.host, self.port, fac, self.authMethods)
        self.proxyEndpoint.connect(proxyFac)
        # XXX: maybe use the deferred returned here? need to more different
        # ways/times a connection can fail before connectionMade is called.
        return proxyFac.deferred
