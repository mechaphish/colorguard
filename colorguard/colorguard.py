import os
import angr
import tracer
import pickle
import hashlib
import claripy
from .harvester import Harvester
from .pov import ColorguardType2Exploit
from .simprocedures import CacheReceive
from .simprocedures import receive
from simuvex.plugins.symbolic_memory import SimSymbolicMemory
from simuvex.storage import SimFile

import logging

l = logging.getLogger("colorguard.ColorGuard")

class ColorGuard(object):
    """
    Detect leaks of the magic flag page data.
    Most logic is offloaded to the tracer.
    """

    def __init__(self, binary, payload, cache_lookup_hook=None, cache_hook=None):
        """
        :param binary: path to the binary which is suspect of leaking
        :param payload: concrete input string to feed to the binary
        :param cache_lookup_hook: cache finding function, returns a state or None
        :param cache_hook: cache function, decides how to cache the state
        """

        self.binary = binary
        self.payload = payload
        self._cache_lookup_hook = self._local_cache_lookup if cache_lookup_hook is None else cache_lookup_hook
        self._cache_hook = self._local_cacher if cache_hook is None else cache_hook

        if not os.access(self.binary, os.X_OK):
            raise ValueError("\"%s\" binary does not exist or is not executable" % self.binary)

        # will be set by hook if needed
        self._cache_file = None

        # will be set by causes_leak
        self._leak_path = None

        receive.cache_hook = self._cache_hook
        self.loaded_from_cache = False
        cache_tuple = self._cache_lookup_hook()

        simprocedures = {'receive': CacheReceive}
        self._tracer = tracer.Tracer(binary, payload, simprocedures=simprocedures)

        # fix up the tracer so that it the input is completely concrete
        if cache_tuple is None:
            e_path = self._tracer.path_group.active[0]
        else:
            p = angr.Project(self.binary)
            bb_cnt, state = cache_tuple

            # fix up executed block count to prevent tracer fix up
            state.scratch.executed_block_count = 0

            pg = p.factory.path_group(state,
                    immutable=True,
                    save_unsat=True,
                    hierarchy=False,
                    save_unconstrained=self._tracer.crash_mode)

            # update path group
            self._tracer.path_group = pg
            # update bb_cnt
            self._tracer.bb_cnt = bb_cnt
            e_path = pg.active[0]

        backing = SimSymbolicMemory(memory_id='file_colorguard')
        backing.set_state(e_path.state)
        backing.store(0, e_path.state.se.BVV(payload))

        e_path.state.posix.files[0] = SimFile('/dev/stdin', 'r', content=backing, size=len(payload))

        self.leak_ast = None

    def _local_cache_lookup(self):

        binhash = hashlib.md5(open(self.binary).read()).hexdigest()
        self._cache_file = os.path.join("/tmp", "%s-%s-rcache" % (os.path.basename(self.binary), binhash))

        if os.path.exists(self._cache_file):
            l.info('loading state from cache file %s', self._cache_file)

            # just for the testcase
            self.loaded_from_cache = True

            # disable the cache_hook if we were able to load from the cache_file
            receive.cache_hook = None

            return pickle.loads(open(self._cache_file).read())

    def _local_cacher(self, state):

        state = self._tracer.previous.state
        ptuple = pickle.dumps((self._tracer.bb_cnt - 1, state))

        l.info('caching state to %s', self._cache_file)
        with open(self._cache_file, 'w') as f:
            f.write(ptuple)

    def causes_leak(self):

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

        # check leaked bits
        simplified = st.se.simplify(self.leak_ast)

        harvester = Harvester(simplified)

        output_var = claripy.BVS('output_var', harvester.minimized_ast.size())

        st.add_constraints(harvester.minimized_ast == output_var)

        ft = self._leak_path.state.se._solver._merged_solver_for(
                lst=[simplified])

        smt_stmt = ft._get_solver().to_smt2()

        return ColorguardType2Exploit(self.binary,
                self.payload, harvester, smt_stmt, output_var)
