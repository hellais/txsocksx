import struct
import parsley

from twisted.trial.unittest import TestCase

from txsocksx.parser import SOCKSGrammar

from txsocksx import errors as e

dummyDomain = 'fuffa.org'
dummyIPV4Addr = '127.0.0.1'
dummyIPV4AddrBytes = \
        struct.pack('!BBBB', *[int(q) for q in dummyIPV4Addr.split('.')])

# 80
dummyPort = '\x00\x50'

dummyClientVersionMethodMessageNoAuthV5 = \
    '\x05\x01\x00'

dummyServerVersionMethodMessageNoAuthV5 = \
    '\x05\x00'

dummySOCKSAddrIPV4 = '\x01' + dummyIPV4AddrBytes
dummySOCKSAddrDomain = '\x04' + chr(len(dummyDomain)) + dummyDomain

dummyClientConnectDomain = \
        '\x05\x01\x00' + dummySOCKSAddrDomain + dummyPort

dummyClientConnectIPV4 = \
        '\x05\x01\x00' + dummySOCKSAddrIPV4 + dummyPort

dummyServerReplySuccessIPV4 = \
        '\x05\x00\x00' + dummySOCKSAddrIPV4 + dummyPort


dummyServerReplyFail1IPV4 = \
        '\x05\x01\x00' + dummySOCKSAddrIPV4 + dummyPort

dummyServerReplyFail2IPV4 = \
        '\x05\x02\x00' + dummySOCKSAddrIPV4 + dummyPort

dummyServerReplyFail3IPV4 = \
        '\x05\x03\x00' + dummySOCKSAddrIPV4 + dummyPort

dummyServerReplyFail4IPV4 = \
        '\x05\x04\x00' + dummySOCKSAddrIPV4 + dummyPort

dummyServerReplyFail5IPV4 = \
        '\x05\x05\x00' + dummySOCKSAddrIPV4 + dummyPort

dummyServerReplyFail6IPV4 = \
        '\x05\x06\x00' + dummySOCKSAddrIPV4 + dummyPort

dummyServerReplyFail7IPV4 = \
        '\x05\x07\x00' + dummySOCKSAddrIPV4 + dummyPort

dummyServerReplyFail8IPV4 = \
        '\x05\x08\x00' + dummySOCKSAddrIPV4 + dummyPort


class TestSOCKSParser(TestCase):
    def test_SOCKSAddressDomain(self):
        p = SOCKSGrammar(dummySOCKSAddrDomain)
        self.assertEqual(p.SOCKSAddress(),
                dummyDomain)

    def test_SOCKSAddrIPV4(self):
        p = SOCKSGrammar(dummySOCKSAddrIPV4)
        self.assertEqual(p.SOCKSAddress(),
                '127.0.0.1')

    def test_hostToSOCKSAddress(self):
        p = SOCKSGrammar(
                dummyDomain
        )
        self.assertEqual(p.hostToSOCKSAddress(),
                    dummySOCKSAddrDomain)

    def test_ClientConnectIPV4(self):
        p = SOCKSGrammar(
                dummyClientConnectIPV4
        )
        self.assertEqual(p.clientRequest(),
                    (1, dummyIPV4Addr, 80))

    def test_ServerReplySuccess(self):
        p = SOCKSGrammar(dummyServerReplySuccessIPV4)
        self.assertEqual(p.serverReply(),
                (0, dummyIPV4Addr, 80))

    def test_ServerReplyServerFailure(self):
        p = SOCKSGrammar(dummyServerReplyFail1IPV4)
        failure, addr, port  = p.serverReply()
        self.assertIs(failure, e.ServerFailure)


    def test_ServerReplyConnectionNotAllowed(self):
        p = SOCKSGrammar(dummyServerReplyFail2IPV4)
        failure, addr, port  = p.serverReply()
        self.assertIs(failure, e.ConnectionNotAllowed)


    def test_ServerReplyNetworkUnreachable(self):
        p = SOCKSGrammar(dummyServerReplyFail3IPV4)
        failure, addr, port  = p.serverReply()
        self.assertIs(failure, e.NetworkUnreachable)


    def test_ServerReplyHostUnreachable(self):
        p = SOCKSGrammar(dummyServerReplyFail4IPV4)
        failure, addr, port  = p.serverReply()
        self.assertIs(failure, e.HostUnreachable)


    def test_ServerReplyConnectionRefused(self):
        p = SOCKSGrammar(dummyServerReplyFail5IPV4)
        failure, addr, port  = p.serverReply()
        self.assertIs(failure, e.ConnectionRefused)


    def test_ServerReplyTTLExpired(self):
        p = SOCKSGrammar(dummyServerReplyFail6IPV4)
        failure, addr, port  = p.serverReply()
        self.assertIs(failure, e.TTLExpired)


    def test_ServerReplyCommandNotSupported(self):
        p = SOCKSGrammar(dummyServerReplyFail7IPV4)
        failure, addr, port  = p.serverReply()
        self.assertIs(failure, e.CommandNotSupported)


    def test_ServerReplyAddressNotSupported(self):
        p = SOCKSGrammar(dummyServerReplyFail8IPV4)
        failure, addr, port  = p.serverReply()
        self.assertIs(failure, e.AddressNotSupported)

