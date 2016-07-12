import claripy
from itertools import groupby
from operator import itemgetter

import logging
l = logging.getLogger("colorguard.harvester")
l.setLevel("DEBUG")


class Harvester(object):
    """
    harvest information from an angr AST
    """

    def __init__(self, ast, state, flag_bytes):
        self.ast = ast

        self.state = state

        self.flag_bytes = flag_bytes

        self.possibly_leaked_bytes = sorted(set(self._get_bytes(self.ast)))

        # receive code
        self.receives = [ ]

        self.minized_ast = None
        self.output_bytes = [ ]

        self._minimize_ast()

    def _minimize_ast(self):
        """
        Byte-by-byte traversal over the AST finding which bytes do not need to
        added to the constraints solved by boolector
        """

        # collect bytes
        ast_bytes = [ ]
        for i in range(self.ast.size() / 8, 0, -1):
            ast_bytes.append(self.ast[i * 8 - 1: (i * 8) - 8])

        # populate receives and minimized ast

        minimized_ast_skel = [ ]

        for i, b in enumerate(ast_bytes):
            if b.op != 'BVV':
                minimized_ast_skel.append(b)
                self.output_bytes.append(i)

        # make the skeleton into an ast
        self.minimized_ast = claripy.Concat(*minimized_ast_skel)

    def _get_bytes(self, ast):
        """
        Get the bytes that might've been leaked
        """
        zen_plugin = self.state.get_plugin("zen_plugin")
        return zen_plugin.get_flag_bytes(ast)

    def _confident_byte(self, ss, byte):
        l.debug("checking byte")
        if len(ss.se.any_n_int(self.flag_bytes[byte], 2)) == 1:
            return True
        return False

    def get_largest_consecutive(self):
        # extra work here because we need to be confident about the bytes

        ss = self.state.copy()
        ss.add_constraints(self.minimized_ast == ss.se.BVV(ss.se.any_str(self.minimized_ast)))

        leaked_bytes = [ ]
        for byte in self.possibly_leaked_bytes:
            if self._confident_byte(ss, byte):
                leaked_bytes.append(byte)

        leaked_bytes = sorted(set(leaked_bytes))

        consec_bytes = [ ]
        # find consecutive leaked bytes
        for _, g in groupby(enumerate(leaked_bytes), lambda (i, x): i-x):
            consec_bytes.append(map(itemgetter(1), g))

        ordered_bytes = sorted(consec_bytes, key=len)
        return ordered_bytes[0] if len(ordered_bytes) > 0 else [ ]
