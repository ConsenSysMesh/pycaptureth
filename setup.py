from setuptools import setup

install_requires = set(x.strip() for x in open('requirements.txt'))

setup(name='captureth',
      version='0.0.5',
      url='http://github.com/Consensys/pycaptureth/',
      description='Capture msgs from pyethapp',
      install_requires=install_requires,
      license='MIT',
      packages=['captureth'])
