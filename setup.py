import subprocess

from setuptools import find_packages, setup

setup(
      name='colorguard',
      version='0.01',
      packages=find_packages(),
      install_requires=[
            'rex',
            'povsim',
            'tracer',
            'angr'
      ],
)
