import nose
import colorguard

import os

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))

def test_simple_leak1():
    """
    Test detection of one of the simplest possible leaks.
    """

    cg = colorguard.ColorGuard(os.path.join(bin_location, 'tests/i386/simple_leak1'), 'foobar')

    nose.tools.assert_true(cg.causes_leak())
    pov = cg.attempt_pov()
    nose.tools.assert_true(pov.test_binary())

def test_simple_leak2():
    """
    Test detection of a leak where multiple arithmetic operations are performed on flag page data.
    """

    cg = colorguard.ColorGuard(os.path.join(bin_location, 'tests/i386/simple_leak2'), 'foobar')

    nose.tools.assert_true(cg.causes_leak())
    pov = cg.attempt_pov()
    nose.tools.assert_true(pov.test_binary())

def test_simple_leak3():
    """
    Test detection of a leak where bytes leaked through different calls to transmit.
    """

    cg = colorguard.ColorGuard(os.path.join(bin_location, 'tests/i386/simple_leak3'), 'foobar')

    nose.tools.assert_true(cg.causes_leak())
    pov = cg.attempt_pov()
    nose.tools.assert_true(pov.test_binary())

def test_simple_leak4():
    """
    Test detection of a leak where bytes leaked through different calls to transmit and operations are done to those bytes.
    """

    cg = colorguard.ColorGuard(os.path.join(bin_location, 'tests/i386/simple_leak4'), 'foobar')

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
