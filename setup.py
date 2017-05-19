#!/usr/bin/env python
import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

setup(
    name='swagman',
    version=open(os.path.join(here, 'VERSION')).read().strip(),
    description='Convert PostMan Collection Report to Swagger file.',
    long_description=open(os.path.join(here, 'README.rst')).read(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
    ],
    keywords=[
        'postman',
        'swagger',
    ],
    author='Florent Pigout',
    author_email='florent.pigout@people-doc.com',
    url='https://github.com/novafloss/swagman',
    license='MIT',
    install_requires=[
        'pyyaml',
    ],
    extras_require={
        'test': [
            'flake8',
            'pytest',
            'pytest-cov',
        ],
        'release': [
            'wheel',
            'zest.releaser'
        ],
    },
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'swagman = swagman:main',
        ]
    }
)
