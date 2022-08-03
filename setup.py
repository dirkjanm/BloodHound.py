from setuptools import setup

setup(name='bloodhound',
      version='1.4.0',
      description='Python based ingestor for BloodHound',
      author='Dirk-jan Mollema, Edwin van Vliet, Matthijs Gielen',
      author_email='dirkjan@dirkjanm.io, edwin.vanvliet@fox-it.com, matthijs.gielen@fox-it.com',
      maintainer='Dirk-jan Mollema',
      maintainer_email='dirkjan@dirkjanm.io',
      url='https://github.com/fox-it/bloodhound.py',
      packages=['bloodhound',
                'bloodhound.ad',
                'bloodhound.lib',
                'bloodhound.enumeration'],
      license='MIT',
      install_requires=['dnspython', 'impacket>=0.9.17', 'ldap3>=2.5,!=2.5.2,!=2.5.0,!=2.6', 'pyasn1>=0.4', 'future'],
      classifiers=[
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
      ],
      entry_points= {
        'console_scripts': ['bloodhound-python=bloodhound:main']
      }
      )
