"""Run every guard. Exits non-zero on the first failure, for CI.

    python tests/run_all.py

Needs no cluster: everything here runs against the matrix and the scoring
engine directly.
"""
import os
import sys
import warnings

warnings.simplefilter('ignore')

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import test_matrix, test_scoring  # noqa: E402

MODULES = [test_matrix, test_scoring]


def main():
    failures = []
    passed = 0

    def report(label, ok, detail=''):
        nonlocal_passed[0] += 1 if ok else 0
        if ok:
            print('  PASS  {0}'.format(label))
        else:
            print('  FAIL  {0}\n          {1}'.format(label, detail))
            failures.append(label)

    nonlocal_passed = [0]

    for module in MODULES:
        print('\n{0}\n{1}\n{0}'.format('=' * 70, module.__name__))
        for test in module.TESTS:
            test(report)

    passed = nonlocal_passed[0]
    print('\n{0}'.format('=' * 70))
    if failures:
        print('FAILED {0} of {1}'.format(len(failures), passed + len(failures)))
        for label in failures:
            print('   ' + label)
        return 1
    print('ALL {0} CHECKS PASSED'.format(passed))
    return 0


if __name__ == '__main__':
    sys.exit(main())
