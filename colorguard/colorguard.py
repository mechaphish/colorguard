import os
import tracer
import claripy
from .harvester import Harvester
from .pov import ColorguardType2Exploit
from simuvex import s_options as so
from simuvex.plugins.symbolic_memory import SimSymbolicMemory
from simuvex.storage import SimFile

import logging

l = logging.getLogger("colorguard.ColorGuard")

class ColorGuard(object):
    """
    Detect leaks of the magic flag page data.
    Most logic is offloaded to the tracer.
    """

    def __init__(self, binary, payload):
        """
        :param binary: path to the binary which is suspect of leaking
        :param payload: concrete input string to feed to the binary
        """

        self.binary = binary
        self.payload = payload

        if not os.access(self.binary, os.X_OK):
            raise ValueError("\"%s\" binary does not exist or is not executable" % self.binary)

        # will be set by causes_leak
        self._leak_path = None

        remove_options = {so.SUPPORT_FLOATING_POINT}
        self._tracer = tracer.Tracer(binary, payload, preconstrain_input=False, remove_options=remove_options)

        e_path = self._tracer.path_group.active[0]

        backing = SimSymbolicMemory(memory_id='file_colorguard')
        backing.set_state(e_path.state)
        backing.store(0, e_path.state.se.BVV(payload))

        e_path.state.posix.files[0] = SimFile('/dev/stdin', 'r', content=backing, size=len(payload))

        # will be overwritten by _concrete_difference if the input was filtered
        # this attributed is used exclusively for testing at the moment
        self._no_concrete_difference = False

        self.leak_ast = None

    def _concrete_difference(self):
        """
        Does an input when ran concretely produce two separate outputs?
        If it causes a leak it should, but if the outputs differ
        it is not guaranteed there is a leak.

        :return: true if the there is a concrete difference
        """

        r1 = tracer.Runner(self.binary, input=self.payload, record_stdout=True, seed=0x41414141)
        r2 = tracer.Runner(self.binary, input=self.payload, record_stdout=True, seed=0x56565656)

        return r1.stdout != r2.stdout

    def causes_leak(self):

        if not self._concrete_difference():
            self._no_concrete_difference = True
            return False

        self._leak_path, _ = self._tracer.run()

        stdout = self._leak_path.state.posix.files[1]

        tmp_pos = stdout.read_pos
        stdout.pos = 0

        output = stdout.read_from(tmp_pos)

        for var in output.variables:
            if var.split("_")[0] == "cgc-flag-data":
                self.leak_ast = output
                return True

        return False

    def attempt_pov(self):

        assert self.leak_ast is not None, "must run causes_leak first or input must cause a leak"

        # switch to a composite solver
        self._tracer.remove_preconstraints(self._leak_path)

        st = self._leak_path.state

        # remove constraints from the state which involve only the flagpage
        new_cons = [ ]
        for con in st.se.constraints:
            if not any(map(lambda x: x.startswith('cgc-flag-data'), list(con.variables))):
                new_cons.append(con)

        st.release_plugin('solver_engine')
        st.add_constraints(*new_cons)
        st.downsize()
        st.se.simplify()
        st.se._solver.result = None

        simplified = st.se.simplify(self.leak_ast)

        harvester = Harvester(simplified)

        output_var = claripy.BVS('output_var', harvester.minimized_ast.size())

        st.add_constraints(harvester.minimized_ast == output_var)

        ft = self._leak_path.state.se._solver._merged_solver_for(
                lst=[simplified])

        smt_stmt = ft._get_solver().to_smt2()

        return ColorguardType2Exploit(self.binary,
                self.payload, harvester, smt_stmt, output_var)
