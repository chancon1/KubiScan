"""Regenerate tests/fixtures/detected_permissions.txt from the current matrix.

Run this ONLY when a permission is deliberately dropped, and say why in the
commit. The whole point of the fixture is that the file changes when detection
changes, so an accidental loss shows up in review as a deleted line.
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from static_risky_roles import STATIC_RISKY_ROLES  # noqa: E402
from tests.helpers import FIXTURE, permission_probes  # noqa: E402


def main():
    probes = permission_probes(STATIC_RISKY_ROLES)
    with io.open(FIXTURE, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write('# Every permission this matrix detects, one per line, as\n')
        handle.write('# apiGroup|resource|verb ("-" apiGroup means a nonResourceURL).\n')
        handle.write('# Regenerate with: python tests/build_baseline.py\n')
        for group, target, verb in probes:
            handle.write('{0}|{1}|{2}\n'.format('-' if group is None else group, target, verb))
    print('wrote {0} permissions to {1}'.format(len(probes), FIXTURE))


if __name__ == '__main__':
    main()
