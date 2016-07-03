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

    def __init__(self, ast):
        self.ast = ast

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

    def get_largest_consecutive(self):

        max_s = -1
        max_bg = [ ]
        for bg in self.bit_groups:
            cur_s = len(bg)
            if cur_s > max_s:
                max_s = cur_s
                max_bg = bg

        # into bytes
        byte_group = [ ]
        for c in chunks(max_bg, 8):
            byte_group.append(c[0] / 8)

        return byte_group

    def count_bytes(self):

        byte_c = 0
        for bg in self.bit_groups:
            byte_c += len(bg) / 8

        return byte_c
