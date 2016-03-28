"""
Non-fonctionnel.
La base est là, mais il faudra se pencher sur quoi rajouter/modifier pour avoir un script d'installation fonctionnel
"""

from setuptools import setup, find_packages


with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='loganalyser',
    version='0.0.1',
    description='Apache log file analyser',
    long_description=readme,
    #author='',
    #author_email='',
    url='https://github.com/Gingerbreadz/ProjetInfo2016',
    #license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)
