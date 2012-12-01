from twisted.internet.error import ConnectionLost
from twisted.internet import defer, protocol
from twisted.python import failure
from twisted.trial import unittest
from twisted.test import proto_helpers

from txsocksx import client, errors, auth

class FakeAuthMethod(object):
    def __init__(self, method):
        self.method = method
        self.negotiated = False

    def negotiate(self, proto):
        self.negotiated = True
        return defer.succeed(None)

class AuthFailed(Exception):
    pass

class FailingAuthMethod(object):
    def __init__(self, method):
        self.method = method

    def negotiate(self, proto):
        return defer.fail(AuthFailed(self.method))

methodA = FakeAuthMethod('A')
methodB = FakeAuthMethod('B')
methodC = FailingAuthMethod('C')
methodD = FailingAuthMethod('D')

connectionLostFailure = failure.Failure(ConnectionLost())

class FakeSOCKS5ClientFactory(protocol.ClientFactory):
    protocol = client.SOCKS5Client

    def __init__(self, authMethods, host=None, port=None):
        self.host = host
        self.port = port
        self.authMethods = authMethods
        self.reason = None
        self.accum = proto_helpers.AccumulatingProtocol()

    def proxyConnectionFailed(self, reason):
        self.reason = reason

    def proxyConnectionEstablished(self, proxyProtocol):
        proxyProtocol.proxyEstablished(self.accum)

class TestSOCKS5Client(unittest.TestCase):
    def makeProto(self, *a, **kw):
        fac = FakeSOCKS5ClientFactory(*a, **kw)
        proto = fac.buildProtocol(None)
        proto.makeConnection(proto_helpers.StringTransport())
        return fac, proto

    def test_initialHandshake(self):
        fac, proto = self.makeProto([methodA])
        self.assertEqual(proto.transport.value(), '\x05\x01A')

        fac, proto = self.makeProto([methodB])
        self.assertEqual(proto.transport.value(), '\x05\x01B')

        fac, proto = self.makeProto([methodA, methodB])
        self.assertEqual(proto.transport.value(), '\x05\x02AB')

    def checkMethod(self, method):
        self.assert_(method.negotiated,
                     'method %r not negotiated' % (method.method,))
        method.negotiated = False

    def test_methodNegotiateAnonymous(self):
        fac, proto = self.makeProto([auth.Anonymous], 'foo.onion', 1080)
        self.assertEqual(proto.transport.value(), '\x05\x01\x00')

    def test_failedMethodSelection(self):
        fac, proto = self.makeProto([auth.Anonymous])
        proto.dataReceived('\x05\xff')
        self.failIfEqual(fac.reason, None)
        self.failUnlessIsInstance(
            fac.reason.value, errors.MethodsNotAcceptedError)

    def checkFailedMethod(self, fac, method):
        self.failIfEqual(fac.reason, None)
        self.failUnlessIsInstance(fac.reason.value, AuthFailed)
        self.assertEqual(fac.reason.value.args[0], method.method)

    def test_connectionRequest(self):
        fac, proto = self.makeProto([auth.Anonymous], 'host', 80)
        self.assertEqual(proto.transport.value(), '\x05\x01\x00')
        proto.transport.clear()
        proto.dataReceived('\x05\x00')
        self.assertEqual(proto.transport.value(),
                         '\x05\x01\x00\x03\x04host\x00P')

        fac, proto = self.makeProto([auth.Anonymous], 'longerhost', 0x9494)
        proto.transport.clear()
        proto.dataReceived('\x05\x00')
        self.assertEqual(proto.transport.value(),
                         '\x05\x01\x00\x03\x0alongerhost\x94\x94')

    def not_implemented_test_connectionRequestError(self):
        fac, proto = self.makeProto([methodA], '', 0)
        proto.dataReceived('\x05\x01\x05\x01\x00\x03\x0022')
        self.failIfEqual(fac.reason, None)
        self.failUnlessIsInstance(fac.reason.value, errors.ConnectionError)
        self.assertEqual(fac.reason.value.args[1], 0x01)

    def not_implemented_test_connectionLostEarly(self):
        wholeRequest = '\x05A\x05\x00\x00\x01444422'
        for e in xrange(len(wholeRequest)):
            partialRequest = wholeRequest[:e]
            fac, proto = self.makeProto([methodA], '', 0)
            if partialRequest:
                proto.dataReceived(partialRequest)
            proto.connectionLost(connectionLostFailure)
            self.failUnlessIsInstance(fac.reason.value, errors.ConnectionLostEarly)

    def not_implemented_test_connectionLost(self):
        fac, proto = self.makeProto([methodA], '', 0)
        proto.dataReceived('\x05A\x05\x00\x00\x01444422')
        proto.connectionLost(connectionLostFailure)
        self.assertEqual(fac.accum.closedReason, connectionLostFailure)

        fac, proto = self.makeProto([methodA], '', 0)
        proto.dataReceived('\x05A\x05\x00\x00\x01444422xxxxx')
        proto.connectionLost(connectionLostFailure)
        self.assertEqual(fac.accum.closedReason, connectionLostFailure)
        self.assertEqual(fac.accum.data, 'xxxxx')

