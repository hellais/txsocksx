

def makeTestFailure():
    l = ['ServerFailure',
         'ConnectionNotAllowed',
         'NetworkUnreachable',
         'HostUnreachable',
         'ConnectionRefused',
         'TTLExpired',
         'CommandNotSupported',
         'AddressNotSupported']

    base = """
        def test_ServerReply%(error_name)s(self):
            p = SOCKSGrammar(dummyServerReplyFail%(idx)sIPV4)
            failure, addr, port  = p.serverReply()
            self.assertIs(failure, e.%(error_name)s)
    """
    for i, v in enumerate(l):
        print base % {'idx': i+1, 'error_name': v}
makeTestFailure()
