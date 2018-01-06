from setuptools import find_packages, setup


setup(name='pw_pcap_helper',
      description='Allow easy manipulation of PCAPs for integration tests',
      url='',
      author='Matt McGuire',
      author_email='matt.mcguire@protectwise.com',
      license='proprietary',
      packages=find_packages(),
      install_requires=[
          'cryptography',
          'ipython',
          'libpcap',
          'matplotlib',
          'netifaces',
          'networkx',
          'pyx',
          'scapy-python3'])
