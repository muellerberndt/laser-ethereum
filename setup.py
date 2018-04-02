from setuptools import setup, find_packages


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

    version='0.5.19',

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
        'mythril',
        'coverage'
    ],

    python_requires='>=3.5',

)
