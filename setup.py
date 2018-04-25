from setuptools import setup, find_packages
from setuptools.command.install import install
import os

# Package version (vX.Y.Z). It must match git tag being used for CircleCI
# deployment; otherwise the build will failed.
VERSION = "v0.16.1"

class VerifyVersionCommand(install):
  """Custom command to verify that the git tag matches our version"""
  description = 'verify that the git tag matches our version'

  def run(self):
      tag = os.getenv('CIRCLE_TAG')

      if (tag != VERSION):
          info = "Git tag: {0} does not match the version of this app: {1}".format(tag, VERSION)
          sys.exit(info)

long_description = '''
LASER
=======

LASER is a symbolic Ethereum virtual machine.

Installation and setup
----------------------

Install from Pypi:

.. code:: bash

    $ pip install laser-ethereum

Usage
------------------

The easiest way to use LASER is by installing Mythril command line tool:

.. code:: bash

    $ pip install mythril
    $ myth --init-db
    $ myth --fire-laser -a [contract-address]

'''


setup(
    name='laser-ethereum',

    version=VERSION[1:],

    description='Symbolic Ethereum virtual machine',
    long_description=long_description,

    author='Bernhard Mueller',
    author_email='bernhard.mueller11@gmail.com',

    license='MIT',

    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Science/Research',
        'Topic :: Software Development :: Testing',

        'License :: Free for non-commercial use',

        'Programming Language :: Python :: 3.5',
    ],

    keywords='hacking security ethereum',

    packages=find_packages(exclude=['contrib', 'docs', 'tests']),

    install_requires=[
        'z3-solver>=4.5',
        'py-flags',
        'coverage'
    ],

    python_requires='>=3.5',

    cmdclass = {
      'verify': VerifyVersionCommand,
    },
)
