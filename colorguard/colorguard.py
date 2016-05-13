import tracer
import harvester
from simuvex.plugins.symbolic_memory import SimSymbolicMemory
from simuvex.storage import SimFile

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

        self._tracer = tracer.Tracer(binary, icontent, preconstrain=False)

        # fix up the tracer so that it the input is completely concrete
        e_path = self._tracer.path_group.active[0]

        backing = SimSymbolicMemory(memory_id='file_colorguard')
        backing.set_state(e_path.state)
        backing.store(0, e_path.state.se.BVV(icontent))

        e_path.state.posix.files[0] = SimFile('/dev/stdin', 'r', content=backing, size=len(icontent))
        e_path.state._colorguard = self

        self.leak_ast = None

    def causes_leak(self):

        path, _ = self._tracer.run()

        stdout = path.state.posix.files[1]

        tmp_pos = stdout.read_pos
        stdout.pos = 0

        output = stdout.read_from(tmp_pos)

        for var in output.variables:
            if var.split("_")[0] == "cgc-flag-data":
                self.leak_ast = output
                return True

        return False

    def attempt_leak(self):

        assert self.leak_ast is not None, "must run causes_leak first or input must cause a leak"

        # convert to C code

        print self.leak_ast
        h = harvester.Harvester(self.leak_ast)
        result = h.reverse()

        print result.leaked_bytes()

        code = h.to_c(result)

        # TODO: make into a pov
        return code
