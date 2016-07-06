import claripy
from itertools import groupby
from operator import itemgetter

def chunks(l, n):
    out = [ ]
    for i in xrange(0, len(l), n):
        out.append(l[i:i+n])

    return out

class Harvester(object):
    """
    harvest information from an angr AST
    """

    def __init__(self, ast, state, flag_var):
        self.ast = ast

        self.state = state

        self.flag_var = flag_var

        self.leaked_bits = set()

        self.bit_groups = [ ]

        self.leaked_bits = sorted(set(self._count_bits_inner(self.ast)))

        for _, g in groupby(enumerate(self.leaked_bits), lambda (i,x):i-x):
            self.bit_groups.append(map(itemgetter(1), g))

        # receive code
        self.receives = [ ]

        # set by count_bits_inner
        self.minized_ast = None

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

        i = 0
        # really ugly code which gathers all receives together
        # so 5 consecutive reads of BVVs becomes a single receive of 5 bytes
        bits_accounted_for = set()
        while i < len(ast_bytes):
            b_cnt = 0
            while i < len(ast_bytes):
                # concrete data or unnecessary leak
                if ast_bytes[i].op == 'BVV'\
                    or set(self._count_bits_inner(ast_bytes[i])).issubset(bits_accounted_for):
                    b_cnt += 1
                    i += 1
                else: break

            if b_cnt > 0:
                self.receives.append("blank_receive(0, %d);" % b_cnt)

            b_cnt = 0
            while i < len(ast_bytes) and ast_bytes[i].op != 'BVV':
                minimized_ast_skel.append(ast_bytes[i])
                # update list of seen bits
                bits_accounted_for = bits_accounted_for.union(set(self._count_bits_inner(ast_bytes[i])))
                b_cnt += 1
                i += 1

            if b_cnt > 0:
                self.receives.append("get_output(%d);" % b_cnt)

        # make the skeleton into an ast
        self.minimized_ast = claripy.Concat(*minimized_ast_skel)

    def _count_bits_inner(self, ast):
        """
        Recursive descent.

        push inverse operation and arguments for each op in original tree
        """

        if not isinstance(ast, claripy.ast.bv.BV):
            return [ ]

        op = ast.op

        bit_cnts = [ ]

        # an extract of the flag page data
        if op == 'Extract' and ast.args[2].op == 'BVS':
            end_index = ast.args[0]
            start_index = ast.args[1]

            # special case if the extract is on the flag page
            if ast.args[2].op == 'BVS':
                sz = ast.args[2].size() - 1
                return map(lambda x: sz - x,
                        range(start_index, end_index+1))

        for arg in ast.args:
            bit_cnts.extend(self._count_bits_inner(arg))

        # no more processing
        return bit_cnts

    def _confident_byte(self, ss, byte):

        for b in byte:
            flag_idx = self.flag_var.size() - 1 - b
            pos = ss.se.any_n_int(self.flag_var[flag_idx], 2)
            if len(pos) > 1:
                return False

        return True

    def get_largest_consecutive(self):

        # extra work here because we need to be confident about the bytes

        ss = self.state.copy()
        ss.add_constraints(self.minimized_ast == ss.se.BVV(ss.se.any_str(self.minimized_ast)))

        leaked_bytes = [ ]
        for bg in self.bit_groups:

            # find the beginning of the bitgroup on the granularity of a byte
            gbg = list(bg)
            while len(gbg) > 0 and gbg[0] % 8 != 0:
                gbg = gbg[1:]

            for byte in chunks(bg, 8):
                if self._confident_byte(ss, byte) and len(byte) == 8:
                    leaked_bytes.append(byte)

        # into bytes
        byte_group = [ ]
        for c in leaked_bytes:
            byte_group.append(c[0] / 8)

        byte_group = sorted(set(byte_group))

        consec_bytes = [ ]
        # find consecutive leaked bytes
        for _, g in groupby(enumerate(byte_group), lambda (i,x):i-x):
            consec_bytes.append(map(itemgetter(1), g))

        ordered_bytes = sorted(consec_bytes, key=len)
        return ordered_bytes[0] if len(ordered_bytes) > 0 else [ ]

    def count_bytes(self):

        byte_c = 0
        for bg in self.bit_groups:
            byte_c += len(bg) / 8

        return byte_c
