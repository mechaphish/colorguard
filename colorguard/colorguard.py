import os
import struct
import tracer
import random
import claripy
import angr
from itertools import groupby
from operator import itemgetter
from .harvester import Harvester
from .pov import ColorguardExploit, ColorguardNaiveExploit, ColorguardNaiveHexExploit, ColorguardNaiveAtoiExploit
from rex.trace_additions import ChallRespInfo, ZenPlugin
from rex.exploit.cgc import CGCExploit
from angr import sim_options as so
from angr.state_plugins.symbolic_memory import SimSymbolicMemory
from angr.storage import SimFile

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

        remove_options = {so.SUPPORT_FLOATING_POINT}
        self._runner = tracer.QEMURunner(binary=binary, input=payload)

        p = angr.misc.tracer.make_tracer_project(binary=binary)
        s = p.factory.tracer_state(input_content=payload,
                                   magic_content=self._runner.magic,
                                   preconstrain_input=False,
                                   remove_options=remove_options)
        self._simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=self._runner.crash_mode)
        t = angr.exploration_techniques.Tracer(trace=self._runner.trace)
        c = angr.exploration_techniques.CrashMonitor(trace=self._runner.trace,
                                                     crash_mode=self._runner.crash_mode,
                                                     crash_addr=self._runner.crash_addr)
        self._simgr.use_technique(c)
        self._simgr.use_technique(t)
        self._simgr.use_technique(angr.exploration_techniques.Oppologist())

        ZenPlugin.prep_tracer(s)

        backing = SimSymbolicMemory(memory_id='file_colorguard')
        backing.set_state(s)
        backing.store(0, s.se.BVV(payload))

        s.posix.files[0] = SimFile('/dev/stdin', 'r', content=backing, size=len(payload))

        # will be overwritten by _concrete_difference if the input was filtered
        # this attributed is used exclusively for testing at the moment
        self._no_concrete_difference = not self._concrete_difference()

        self.leak_ast = None

    def _concrete_leak_info(self, seed=None):

        if seed is None:
            seed = random.randint(0, 2**32)

        r1 = tracer.QEMURunner(self.binary, input=self.payload, record_magic=True, record_stdout=True, seed=seed)

        return (r1.stdout, r1.magic)

    def _concrete_difference(self):
        """
        Does an input when ran concretely produce two separate outputs?
        If it causes a leak it should, but if the outputs differ
        it is not guaranteed there is a leak.

        :return: True if the there is a concrete difference
        """

        s1, _ = self._concrete_leak_info()
        s2, _ = self._concrete_leak_info()

        return s1 != s2

    def causes_dumb_leak(self):

        return not self._no_concrete_difference

    def _find_dumb_leaks_raw(self):

        s1, m1 = self._concrete_leak_info()

        potential_leaks = [ ]
        for i in xrange(len(s1)):
            pchunk = s1[i:i+4]
            if len(pchunk) == 4 and pchunk in m1:
                potential_leaks.append(i)

        return potential_leaks

    def _find_dumb_leaks_hex(self):

        s1, m1 = self._concrete_leak_info()

        potential_leaks = [ ]
        for i in xrange(len(s1)):
            pchunk = s1[i:i+8]
            if len(pchunk) == 8 and pchunk in m1.encode('hex'):
                potential_leaks.append(i)

        return potential_leaks

    def _find_dumb_leaks_atoi(self):

        s1, m1 = self._concrete_leak_info()

        potential_leaks = []
        for i in xrange(len(m1)):
            pchunk = m1[i:i+4]
            if len(pchunk) != 4:
                continue
            val = struct.unpack("<I", pchunk)[0]
            if str(val) in s1:
                potential_leaks.append(s1.find(str(val)))
            val2 = -((1 << 32) - val)
            if str(val2) in s1:
                potential_leaks.append(s1.find(str(val2)))
        return potential_leaks

    def attempt_dumb_pov_raw(self):

        p1 = self._find_dumb_leaks_raw()
        p2 = self._find_dumb_leaks_raw()

        leaks = list(set(p1).intersection(set(p2)))

        if leaks:
            leaked_bytes = range(leaks[0], leaks[0]+4)
            l.info("Found dumb leak which leaks bytes %s", leaked_bytes)

            return ColorguardNaiveExploit(self.binary, self.payload, leaked_bytes[-1]+1, leaked_bytes)
        else:
            l.debug("No dumb leak found")

    def attempt_dumb_pov_hex(self):

        p1 = self._find_dumb_leaks_hex()
        p2 = self._find_dumb_leaks_hex()

        leaks = list(set(p1).intersection(set(p2)))

        if leaks:
            leaked_bytes = range(leaks[0], leaks[0]+8)
            l.info("Found dumb hex leak which leaks bytes %s", leaked_bytes)

            return ColorguardNaiveHexExploit(self.binary, self.payload, leaked_bytes[-1]+1, leaked_bytes)
        else:
            l.debug("No dumb hex leak found")

    def attempt_dumb_pov_atoi(self):
        p1 = self._find_dumb_leaks_atoi()
        p2 = self._find_dumb_leaks_atoi()

        leaks = list(set(p1).intersection(set(p2)))

        if leaks:
            leak_start = leaks[0]
            l.info("Found dumb atoi leak which leaks at byte %s", leak_start)

            return ColorguardNaiveAtoiExploit(self.binary, self.payload, leak_start)
        else:
            l.debug("No dumb leak found")

    def attempt_dumb_pov(self):

        pov = self.attempt_dumb_pov_raw()
        if pov is not None:
            return pov

        pov = self.attempt_dumb_pov_hex()
        if pov is not None:
            return pov

        pov = self.attempt_dumb_pov_atoi()
        if pov is not None:
            return pov

    def causes_naive_leak(self):

        return self.causes_dumb_leak()

    def _find_naive_leaks(self, seed=None):
        """
        Naive implementation of colorguard which looks for concrete leaks of
        the flag page.
        """

        stdout, magic = self._concrete_leak_info(seed=seed)

        # byte indices where a leak might have occured
        potential_leaks = dict()
        for si, b in enumerate(stdout):
            try:
                indices = [i for i, x in enumerate(magic) if x == b]
                potential_leaks[si] = indices
            except ValueError:
                pass

        return potential_leaks

    def attempt_naive_pov(self):

        p1 = self._find_naive_leaks()
        p2 = self._find_naive_leaks()

        leaked = dict()
        for si in p1:
            if si in p2:
                li = list(set(p2[si]).intersection(set(p1[si])))
                if len(li) > 0:
                    for lb in li:
                        leaked[lb] = si

        # find four contiguous
        consecutive_groups = [ ]
        for _, g in groupby(enumerate(sorted(leaked)), lambda (i,x):i-x):
            consecutive_groups.append(map(itemgetter(1), g))

        lgroups = filter(lambda x: len(x) >= 4, consecutive_groups)

        if len(lgroups):
            l.info("Found naive leak which leaks bytes %s", lgroups[0])
            leaked_bytes = [ ]
            for b in leaked:
                leaked_bytes.append(leaked[b])

            return ColorguardNaiveExploit(self.binary, self.payload, max(leaked_bytes)+1, leaked_bytes)
        else:
            l.debug("No naive leak found")

    def causes_leak(self):

        if not self.causes_naive_leak():
            return False

        self._simgr.run()

        self._leak_path = self._simgr.traced[0]

        stdout = self._leak_path.posix.files[1]
        tmp_pos = stdout.read_pos
        stdout.pos = 0

        output = stdout.read_from(tmp_pos)

        for var in output.variables:
            if var.startswith("cgc-flag"):
                self.leak_ast = output
                return True

        return False

    def attempt_pov(self, enabled_chall_resp=False):

        assert self.leak_ast is not None, "must run causes_leak first or input must cause a leak"

        st = self._leak_path

        # switch to a composite solver
        st.preconstrainer.remove_preconstraints(simplify=False)

        # get the flag var
        flag_bytes = st.cgc.flag_bytes

        # remove constraints from the state which involve only the flagpage
        # this solves a problem with CROMU_00070, where the floating point
        # operations have to be done concretely and constrain the flagpage
        # to being a single value
        CGCExploit.filter_uncontrolled_constraints(st)

        simplified = st.se.simplify(self.leak_ast)

        harvester = Harvester(simplified, st.copy(), flag_bytes)

        output_var = claripy.BVS('output_var', harvester.minimized_ast.size(), explicit_name=True) #pylint:disable=no-member

        st.add_constraints(harvester.minimized_ast == output_var)

        leaked_bytes = harvester.get_largest_consecutive()
        if len(leaked_bytes) < 4:
            l.warning("input does not leak enough bytes, %d bytes leaked, need 4", len(leaked_bytes))
            return None

        exploit = ColorguardExploit(self.binary, st,
                                    self.payload, harvester,
                                    simplified, output_var, leaked_bytes)

        # only want to try this once
        if not enabled_chall_resp:
            l.info('testing for challenge response')
            if self._challenge_response_exists(exploit):
                l.warning('challenge response detected')
                exploit = self._prep_challenge_response()

        return exploit

    def attempt_exploit(self):
        """
        Try all techniques
        """

        if self.causes_dumb_leak():
            pov = self.attempt_dumb_pov()
            if pov is not None and any(pov.test_binary(times=10, enable_randomness=True, timeout=5)):
                return pov
            else:
                l.warning("Dumb leak exploitation failed")

        if self.causes_naive_leak():
            pov = self.attempt_naive_pov()
            if pov is not None and any(pov.test_binary(times=10, enable_randomness=True, timeout=5)):
                return pov
            else:
                l.warning("Naive leak exploitation failed")

        if self.causes_leak():
            pov = self.attempt_pov()
            if pov is not None:
                return pov
            else:
                l.warning("Colorguard leak exploitation failed")

### CHALLENGE RESPONSE

    @staticmethod
    def _challenge_response_exists(exploit):
        """
        Since one success may actually occur, let's test for two successes
        """

        return not (exploit.test_binary(times=10, enable_randomness=True, timeout=30).count(True) > 1)

    def _prep_challenge_response(self, format_infos=None):

        # need to re-trace the binary with stdin symbolic

        remove_options = {so.SUPPORT_FLOATING_POINT}

        p = angr.misc.tracer.make_tracer_project(binary=self.binary)
        s = p.factory.tracer_state(input_content=self.payload,
                                   magic_content=self._runner.magic,
                                   remove_options=remove_options)
        self._simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=self._runner.crash_mode)
        t = angr.exploration_techniques.Tracer(trace=self._runner.trace)
        c = angr.exploration_techniques.CrashMonitor(trace=self._runner.trace,
                                                     crash_mode=self._runner.crash_mode,
                                                     crash_addr=self._runner.crash_addr)
        self._simgr.use_technique(c)
        self._simgr.use_technique(t)
        self._simgr.use_technique(angr.exploration_techniques.Oppologist())

        ZenPlugin.prep_tracer(s)

        ChallRespInfo.prep_tracer(s, format_infos)

        assert self.causes_leak(), "challenge did not cause leak when trying to recover challenge-response"

        return self.attempt_pov(enabled_chall_resp=True)
