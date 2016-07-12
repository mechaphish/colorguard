import os
import tracer
import random
import claripy
from itertools import groupby
from operator import itemgetter
from .harvester import Harvester
from .pov import ColorguardExploit, ColorguardNaiveExploit
from rex.trace_additions import ChallRespInfo
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

    def __init__(self, binary, payload, format_infos=None):
        """
        :param binary: path to the binary which is suspect of leaking
        :param payload: concrete input string to feed to the binary
        :param format_infos: a list of atoi FormatInfo objects that should be used when analyzing the crash
        """

        self.binary = binary
        self.payload = payload

        if not os.access(self.binary, os.X_OK):
            raise ValueError("\"%s\" binary does not exist or is not executable" % self.binary)

        # will be set by causes_leak
        self._leak_path = None

        # list of bytes leaked through the naive method
        self._naively_leaked_bytes = [ ]

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

        # mark a flag so we can test this method's effectiveness
        self._no_concrete_difference = r1.stdout == r2.stdout

        return not self._no_concrete_difference

    def _find_naive_leaks(self, seed=None):
        """
        Naive implementation of colorguard which looks for concrete leaks of
        the flag page.
        """

        if seed is None:
            seed = random.randint(0, 2**32)

        r1 = tracer.Runner(self.binary,
                input=self.payload,
                record_magic=True,
                record_stdout=True,
                seed=seed)

        magic = r1.magic

        stdout = r1.stdout

        # byte indices where a leak might have occured
        potential_leaks = dict()
        for si, b in enumerate(stdout):
            try:
                indices = [i for i, x in enumerate(magic) if x == b]
                potential_leaks[si] = indices
            except ValueError:
                pass

        return (potential_leaks, stdout)

    def attempt_naive_pov(self):

        p1, stdout = self._find_naive_leaks()
        p2, _ = self._find_naive_leaks()

        leaked = dict()
        for si in p1.keys():
            if si in p2:
                li = list(set(p2[si]).intersection(set(p1[si])))
                if len(li) > 0:
                    for lb in li:
                        leaked[lb] = si

        # find four contiguous
        consecutive_groups = [ ]
        for _, g in groupby(enumerate(sorted(leaked.keys())), lambda (i,x):i-x):
            consecutive_groups.append(map(itemgetter(1), g))

        lgroups = filter(lambda x: len(x) >= 4, consecutive_groups)

        if len(lgroups):
            l.info("Found naive leak which leaks bytes %s", lgroups[0])
            for b in leaked.keys():
                self._naively_leaked_bytes.append(leaked[b])

            return ColorguardNaiveExploit(self.binary, self.payload, len(stdout), self._naively_leaked_bytes)
        else:
            l.debug("No naive leak found")

    def causes_naive_leak(self):

        return self._concrete_difference()

    def causes_leak(self):

        if not self.causes_naive_leak():
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

    def attempt_pov(self, enabled_chall_resp=False):

        assert self.leak_ast is not None, "must run causes_leak first or input must cause a leak"

        st = self._leak_path.state

        # switch to a composite solver
        self._tracer.remove_preconstraints(self._leak_path, simplify=False)

        # remove constraints from the state which involve only the flagpage
        # this solves a problem with CROMU_00070, where the floating point
        # operations have to be done concretely and constrain the flagpage
        # to being a single value
        # FIXME chris look at this, does it filter anything
        new_cons = [ ]
        for con in st.se.constraints:
            if not (len(con.variables) == 1 and list(con.variables)[0].startswith('cgc-flag-data')):
                new_cons.append(con)

        st.release_plugin('solver_engine')
        st.add_constraints(*new_cons)
        st.downsize()
        st.se.simplify()
        st.se._solver.result = None

        simplified = st.se.simplify(self.leak_ast)

        flag_vars = filter(lambda x: x.startswith('cgc-flag-data'), list(self.leak_ast.variables))
        assert len(flag_vars) == 1, "multiple flag variables, requires further attention"
        flag_var = claripy.BVS(flag_vars[0], 0x1000 * 8, explicit_name=True)

        harvester = Harvester(simplified, st.copy(), flag_var)

        output_var = claripy.BVS('output_var', harvester.minimized_ast.size(), explicit_name=True) #pylint:disable=no-member

        st.add_constraints(harvester.minimized_ast == output_var)

        exploit = ColorguardExploit(self.binary, st,
                                    self.payload, harvester,
                                    simplified, output_var)

        # only want to try this once
        if not enabled_chall_resp:
            l.info('testing for challenge response')
            if self._challenge_response_exists(exploit):
                l.warning('challenge response detected')
                exploit = self._prep_challenge_response()

        return exploit

### CHALLENGE RESPONSE

    @staticmethod
    def _challenge_response_exists(exploit):

        for _ in range(10):
            if exploit.test_binary(enable_randomness=True):
                return False

        return True

    def _prep_challenge_response(self, format_infos=None):

        # need to re-trace the binary with stdin symbolic

        remove_options = {so.SUPPORT_FLOATING_POINT}
        self._tracer = tracer.Tracer(self.binary, self.payload, remove_options=remove_options)
        ChallRespInfo.prep_tracer(self._tracer, format_infos)

        assert self.causes_leak(), "challenge did not cause leak when trying to recover challenge-response"

        return self.attempt_pov(enabled_chall_resp=True)
