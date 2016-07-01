import nose
import logging
import colorguard

import os

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))

#logging.getLogger("tracer").setLevel("DEBUG")
#logging.getLogger("simuvex.plugins.unicorn").setLevel("DEBUG")
logging.getLogger("colorguard").setLevel("DEBUG")
logging.getLogger("rex").setLevel("DEBUG")

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

def test_big_leak():
    """
    Test detection of a leak where 0x8000 concrete bytes are written to stdout before a the secret is leaked.
    This used to cause a bug because of limits placed on how much data could be loaded from a SymbolicMemoryRegion.
    """

    cg = colorguard.ColorGuard(os.path.join(bin_location, 'tests/i386/big_leak'), 'foobar')

    nose.tools.assert_true(cg.causes_leak())
    pov = cg.attempt_pov()
    nose.tools.assert_true(pov.test_binary())

def test_double_leak():
    """
    Test detection of a leak where the same bytes are leaked twice. Once they are leaked in a reversable operation,
    the second time they are leaked the operation is not reversible.
    This should test the ability for colorguard to only choose attempting to reverse the the operation which we know
    is reversable.
    """

    payload = "320a310a0100000005000000330a330a340a".decode('hex')
    cg = colorguard.ColorGuard(os.path.join(bin_location, 'shellphish/PIZZA_00001'), payload)

    nose.tools.assert_true(cg.causes_leak())
    pov = cg.attempt_pov()
    nose.tools.assert_true(pov.test_binary())

def test_caching():
    """
    Test the at-receive local caching.
    """

    payload = "320a310a0100000005000000330a330a340a".decode('hex')
    cg1 = colorguard.ColorGuard(os.path.join(bin_location, 'shellphish/PIZZA_00001'), payload)

    # of course run the thing and makes sure it works
    nose.tools.assert_true(cg1.causes_leak())

    cg2 = colorguard.ColorGuard(os.path.join(bin_location, 'shellphish/PIZZA_00001'), payload)

    nose.tools.assert_true(cg2.loaded_from_cache)

    # and insure the cache-loaded version still works
    nose.tools.assert_true(cg2.causes_leak())
    pov = cg2.attempt_pov()
    nose.tools.assert_true(pov.test_binary())

def test_leak_no_exit():
    """
    Test the handling of leaks where the payload does not cause an exit of the binary.
    """

    # this payload cause a leak but the exit condition in QEMU does not represent the
    # the PoV's running environment accurately
    payload = "320a330a".decode('hex')
    cg = colorguard.ColorGuard(os.path.join(bin_location, 'shellphish/PIZZA_00001'), payload)

    # of course run the thing and makes sure it works
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
