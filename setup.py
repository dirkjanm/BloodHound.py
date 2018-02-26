from setuptools import setup

setup(name='bloodhound',
      version='0.1.0',
      description='Python based ingestor for BloodHound',
      author='Edwin van Vliet, Dirk-jan Mollema, Matthijs Gielen',
      author_email='edwin.vanvliet@fox-it.com, dirkjan.mollema@fox-it.com, matthijs.gielen@fox-it.com',
      url='https://github.com/fox-it/bloodhound.py',
      packages=['bloodhound'],
      license='MIT',
      install_requires=['dnspython','impacket'],
      classifiers=[
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7'
      ],
      entry_points= {
        'console_scripts': ['bloodhound-python=bloodhound:main']
      }
      )
