from abc import ABCMeta, abstractmethod
import re


class Fichier:
    """Classe abstraite interface pour fichier caractérisé par :
    - son nombre de ligne
    - son contenu
    - son chemin d'accès
    - si il est read-only ou non"""

    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, filepath):
        """Constructeur de classe. Un fichier est initialisé à partir de son chemin d'accès
        :param filepath: chemin d'accès du fichier
        :type filepath: str"""
        self.file = open(filepath, 'r')
        self.chemin=filepath
        self.contenu=list(self.file)
        self.nbLigne=len(self.contenu)
        self.ro=True
        return

    @abstractmethod
    def lireligne(self, noligne):
        """Retourne la ligne n d'un fichier
        :param noligne: numero de la ligne voulu
        :type noligne: int
        :return: ligne n du fichier instancié
        :rtype: str"""
        return self.contenu[noligne]

    @abstractmethod
    def ecriretexte(self, data):
        """Ecrit les lignes en entrée à la fin du fichier
        :param data: numero de la ligne voulu
        :type data: list"""
        for ligne in data:
            self.file.write(ligne + "\n")
            self.nbLigne += 1
            self.contenu.append(ligne)
        return

    @abstractmethod
    def fermerfichier(self):
        """Ferme le fichier pour libérer des ressources"""
        self.file.close()
        return

    @abstractmethod
    def decouperligne(self, noligne):
        """Decoupage syntaxique de la n-ieme ligne
        :param noligne: Numéro de ligne
        :type noligne: int
        :return: Liste contenant les différents champs découpés.
        :rtype: xxx"""


class FichierDeLog(Fichier):

    """Classe instanciant des fichiers de log caractérisé par :
        - son nombre de ligne
        - son contenu
        - son chemin d'accès
        - si il est read-only ou non"""

    # RegExp utilisée pour le découpage du fichier
    c_reg=re.compile(r'^(.+)-(.*)\[(.+)[-|+](\d+)\] "([A-Z]+)?(.+) HTTP/\d.\d" (\d+)(\s[\d]+)?(\s"(.+)" )?(.*)$')

    def __init__(self, filepath):
        super(FichierDeLog,self).__init__(filepath)
        return

    def lireligne(self, noligne):
        super(FichierDeLog, self).lireligne(noligne)
        return

    def fermerfichier(self):
        super(FichierDeLog, self).fermerfichier
        return

    def decouperligne(self, noligne):
        super(FichierDeLog, self).decouperligne(noligne)
        return


class FichierRegExp(Fichier):
    """Classe instanciant des fichiers d'expressions régulières caractérisé par :
        - son nombre de ligne
        - son contenu
        - son chemin d'accès
        - si il est read-only ou non"""

    def __init__(self, filepath):
        super(FichierRegExp, self).__init__(filepath)
        return

    def lireligne(self, noligne):
        super(FichierRegExp, self).lireligne(noligne)
        return

    def fermerfichier(self):
        super(FichierRegExp, self).fermerfichier()
        return

    def decouperligne(self, noligne):
        super(FichierRegExp, self).decouperligne(noligne)
        return


class FichierRapportTextuel(Fichier):
    """Classe instanciant le rapport textuel caractérisé par :
        - son nombre de ligne
        - son contenu
        - son chemin d'accès
        - si il est read-only ou non"""

    def __init__(self, filepath):
        """Constructeur de classe. Un fichier est initialisé à partir de son chemin d'accès
            :param filepath: chemin d'accès du fichier
            :type filepath: str"""
        self.file = open(filepath, 'w')
        self.chemin = filepath
        self.contenu = []
        self.nbLigne = 0
        self.ro = False
        return

    def lireligne(self):
        super(FichierRapportTextuel, self).lireligne()
        return

    def fermerfichier(self):
        super(FichierRapportTextuel, self).fermerfichier()
        return

    def ecriretexte(self, data):
        super(FichierRapportTextuel, self).ecriretexte(data)
        return