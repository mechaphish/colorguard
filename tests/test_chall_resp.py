import nose
import logging
import colorguard

import os

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))

logging.getLogger("colorguard").setLevel("DEBUG")
logging.getLogger("povsim").setLevel("DEBUG")

def test_simple_chall_resp():
    cg = colorguard.ColorGuard(os.path.join(bin_location, "tests/i386/CUSTM_00022"), '\xa0\x9d\x9a\x35AA')

    nose.tools.assert_true(cg.causes_leak())
    pov = cg.attempt_pov()
    nose.tools.assert_true(pov.test_binary())


def test_fast_avoid_solves():
    import tracer
    tracer.tracer.l.setLevel("DEBUG")
    cg = colorguard.ColorGuard(os.path.join(bin_location, "tests/i386/chall_resp_leak2"), 'Zw\xd4V')

    nose.tools.assert_true(cg.causes_leak())
    pov = cg.attempt_pov()
    nose.tools.assert_true(pov.test_binary())

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
