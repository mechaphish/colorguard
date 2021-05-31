import os

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    packages = []
    for root, _, filenames in os.walk(PROJECT_DIR):
        if '__init__' in filenames:
            packages.append(root)

from distutils.command.build import build as _build

def build(_build):
    def run(self):
        _build.run(self)

cmd_class = {'build' : build}

setup(
      name='colorguard',
      version='0.01',
      packages=packages,
    cmd_class = cmd_class,
      install_requires=[
            'rex',
            'povsim',
            'tracer',
            'angr'
      ],
    package_data={'colorguard': ['__init__.py', 'colorguard.py','pov/*',
                                 'pov/c_templates/*', 'harvester/*'],
    },
)
