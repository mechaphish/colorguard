import logging
import colorguard

import os

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))

def test_simple_chall_resp():
    cg = colorguard.ColorGuard(os.path.join(bin_location, "tests/cgc/CUSTM_00022"), b'\xa0\x9d\x9a\x35AA')

    assert cg.causes_leak()
    pov = cg.attempt_pov()
    assert pov.test_binary()


def test_fast_avoid_solves():
    cg = colorguard.ColorGuard(os.path.join(bin_location, "tests/cgc/chall_resp_leak2"), b'Zw\xd4V')

    assert cg.causes_leak()
    pov = cg.attempt_pov()
    assert pov.test_binary()

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    logging.getLogger("colorguard").setLevel("DEBUG")
    logging.getLogger("povsim").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
