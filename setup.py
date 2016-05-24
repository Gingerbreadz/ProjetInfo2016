"""
Non-fonctionnel.
La base est là, mais il faudra se pencher sur quoi rajouter/modifier pour avoir un script d'installation fonctionnel
"""

from setuptools import setup, find_packages

setup(
    name='loganalyser',
    version='0.0.1',
    description='Apache log file analyser',
    #author='',
    #author_email='',
    url='https://github.com/Gingerbreadz/ProjetInfo2016',
    license="TSP",
    packages=['loganalyser'],
    entry_points={
        "console_scripts": ['loganalyser = loganalyser.__main__:main']
    },
    package_data={'': ['./res/default_filter.xml']},
    data_files = [('', ['./res/default_filter.xml',]),]
)
