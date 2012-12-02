from twisted.internet import defer
from txsocksx.errors import SOCKSError

class Anonymous(object):
    """
    ( 0 )
    """
    def negotiate(self, proto):
        pass

class GSSAPI(object):
    """
    ( 1 )
    """
    def negotiate(self, proto):
        raise NotImplemented

class UsernamePasswordAuthFailed(SOCKSError):
    pass

class UsernamePassword(object):
    """
    ( 2 )
    """
    def __init__(self, uname, passwd):
        self.uname = uname
        self.passwd = passwd

    def negotiate(self, proto):
        proto.transport.write(
            '\x01'
            + chr(len(self.uname)) + self.uname
            + chr(len(self.passwd)) + self.passwd)
