import nose
from nose.plugins.attrib import attr
import logging
import colorguard

import os

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))

@attr(speed='slow')
def test_cromu_00070_caching():
    # Test exploitation of CROMU_00070 given an input which causes a leak. Then test that we can do it again restoring
    # from the cache.

    for _ in range(2):
        payload = bytes.fromhex("06000006020a00000000000000000000000c030c00000100e1f505000000000000eb")
        cg = colorguard.ColorGuard(os.path.join(bin_location, "tests/cgc/CROMU_00070"), payload)

        pov = cg.attempt_exploit()
        nose.tools.assert_not_equal(pov, None)
        nose.tools.assert_true(pov.test_binary())

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    logging.getLogger("colorguard").setLevel("DEBUG")
    logging.getLogger("povsim").setLevel("DEBUG")

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
