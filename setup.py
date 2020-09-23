
#!/usr/bin/env python
from setuptools import setup, find_packages
import os


data_files = [(d, [os.path.join(d, f) for f in files])
              for d, folders, files in os.walk(os.path.join('src', 'config'))]


setup(name='docker-honeypot',
      version='.01',
      description='docker honeypot used to capture attempted CREATE API calls',
      author='Adam Pridgen',
      author_email='adpridge@cisco.com',
      install_requires=['wheel', 'quart', 'mongoengine', 'regex', 'validators',
                        'ipython', 'flask', 'flask_restful', 'requests', "validator-collection",
                        'paramiko', 'boto3', 'netifaces', 'scp', 'hypercorn'],
      packages=find_packages('src'),
      package_dir={'': 'src'},
)
