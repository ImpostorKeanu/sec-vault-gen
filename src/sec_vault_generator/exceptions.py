class Error(Exception):
    pass

class InsufficientPrivileges(Error):
    pass

class RequestError(Error):
    pass
