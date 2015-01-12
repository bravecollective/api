#!/usr/bin/env python

import sys, os
from setuptools import setup, find_packages

setup(
        name = "braveapi",
        version = "0.1",
        description = "Python API bindings for both utilizing and hosting the secure RPC mechanism.",
        author = "Alice Bevan-McGregor",
        author_email = "alice@gothcandy.com",
        license = "MIT",
        
        packages = find_packages(),
        include_package_data = True,
        zip_safe = False,
        namespace_packages = ['braveapi'],
        
        tests_require = ['nose', 'webtest', 'coverage'],
        test_suite = 'nose.collector',
        
        install_requires = [
                'WebOb',
                'marrow.util',
                'ecdsa',
                'futures'
            ],
        
    )
