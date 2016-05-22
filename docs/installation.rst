============
Installation
============

Le projet reprend la structure standard d'un package Python, et peut donc facilement être installé via le ``setup.py``.
Conçu pour ``python3.X``, il convient avant de procéder à l'installation de s'assurer de la version de l'environnement
Python courant.

Installation directe
====================

Cette procedure installera le package au sein de Python comme module. Le projet a été conçu pour que les étapes à suivre
soient les même que pour tout autre module.

Il est possible de se placer, avant d'initier la procedure, dans un environnement Python virtuelle ``venv`` si
l'environnement courant n'est pas approprié.

.. code-block:: bash

    $ git clone https://github.com/Gingerbreadz/ProjetInfo2016
    $ cd ./ProjetInfo2016
    $ python setup.py install

Installation dans pip
=====================

Une procédure alternative permet d'installer le projet comme package ``pip`` et ainsi de plus facilement le désinstaller.
Le projet n'étant pas disponible sur les dépots PyPi, l'installation se déroule comme suit.

.. code-block:: bash

    $ git clone https://github.com/Gingerbreadz/ProjetInfo2016
    $ cd ./ProjetInfo2016
    $ python setup.py sdist
    $ pip install ./dist/loganalyser-0.0.1.tar.gz

La désinstallation peut alors être faite avec un ``pip uninstall`` comme pour tout autre package pip. En cas de
difficultés à identifier le nom du package, ``pip freeze`` permet de lister tout les package pip installés dans
l'environnement Python courant.