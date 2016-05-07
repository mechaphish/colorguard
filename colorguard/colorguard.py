import tracer
from .simprocedures import ColorGuardTransmitHook, FlagLeakDetected

class ColorGuard(object):
    """
    Detect leaks of the magic flag page data.
    Most logic is offloaded to the tracer.
    """

    def __init__(self, binary, icontent):
        """
        :param binary: path to the binary which is suspect of leaking
        :param icontent: concrete input string to feed to the binary
        """

        self._tracer = tracer.Tracer(binary, icontent, simprocedures={'transmit': ColorGuardTransmitHook})

        __import__("ipdb").set_trace()
        self._tracer.path_group

    def causes_leak(self):

        try:
            self._tracer.run()
        except FlagLeakDetected:
            return True

        return False
