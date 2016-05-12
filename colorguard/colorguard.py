import tracer
import harvester
from simuvex.plugins.symbolic_memory import SimSymbolicMemory
from simuvex.storage import SimFile

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

        self._tracer = tracer.Tracer(binary, icontent, preconstrain=False, simprocedures={'transmit': ColorGuardTransmitHook})


        # fix up the tracer so that it the input is completely concrete
        e_path = self._tracer.path_group.active[0]

        backing = SimSymbolicMemory(memory_id='file_colorguard')
        backing.set_state(e_path.state)
        backing.store(0, e_path.state.se.BVV(icontent))

        e_path.state.posix.files[0] = SimFile('/dev/stdin', 'r', content=backing, size=len(icontent))

        self.sym_bytes = [ ]

    def causes_leak(self):

        try:
            self._tracer.run()
        except FlagLeakDetected as fld:
            self.sym_bytes.append(fld.args[0])
            return True

        return False

    def attempt_leak(self):

        assert len(self.sym_bytes) > 0, "run causes_leak before attempting to exploit"

        # TODO: detect if we have four contiguous bytes

        sym_bytes = self.sym_bytes[0]

        # convert to C code
        h = harvester.Harvester(sym_bytes)
        h.reverse()

        code = h.to_c()

        # TODO: make into a pov
