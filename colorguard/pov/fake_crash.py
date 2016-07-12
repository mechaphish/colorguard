import angr

class FakeCrash(object):

    def __init__(self, binary, state):
        self.binary = binary
        self.state = state
        self.project = angr.Project(self.binary)
