"""
Sert à intéragir avec les fichiers.
"""


from abc import ABCMeta, abstractmethod
import re
import xml.etree.ElementTree as Etree

# c_reg = re.compile('([^ ]*) ([^ ]*) ([^ ]*) \[([^]]*)\] "([^"]*)" ([^ ]*) ([^ ]*)'' "([^"]*)" "([^"]*)"')
c_reg = re.compile('(.+) - (-.*)\[(.+) [-|+](\d+)\] "([A-Z]+) ?(.+) HTTP/\d.\d" (\d+)(\s[\d]+)? "(.+)" (.*)$')


class Fichier:
    """Classe abstraite interface pour fichier caractérisé par :

    - son nombre de ligne
    - son contenu
    - son chemin d'accès
    - si il est read-only ou non

    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, filepath):
        """
        Constructeur de classe. Un fichier est initialisé à partir de son chemin d'accès

        :param filepath: chemin d'accès du fichier
        :type filepath: str

        """
        self.file = open(filepath, 'r')
        self.chemin = filepath
        self.contenu = list(self.file)
        self.nbLigne = len(self.contenu)
        self.ro = True
        return

    @abstractmethod
    def lireligne(self, noligne):
        """
        Retourne la ligne n d'un fichier

        :param noligne: numero de la ligne voulu
        :type noligne: int
        :return: ligne n du fichier instancié
        :rtype: str

        """
        return self.contenu[noligne]

    @abstractmethod
    def fermerfichier(self):
        """Ferme le fichier pour libérer des ressources"""
        self.file.close()
        return


class FichierDeLog(Fichier):

    """Classe instanciant des fichiers de log caractérisé par :

    - son nombre de ligne
    - son contenu
    - son chemin d'accès
    - si il est read-only ou non

    """

    # RegExp utilisée pour le découpage du fichier (combined log format)

    def __init__(self, filepath):
        super().__init__(filepath)

    def lireligne(self, noligne):
        return super().lireligne(noligne)

    def fermerfichier(self):
        super(FichierDeLog, self).fermerfichier()

    def decouperligne(self, noligne):
        """
        Decoupage syntaxique de la n-ieme ligne pour séparer les différents token

        :param noligne: Numéro de ligne
        :type noligne: int
        :return: Liste contenant les différents champs découpés.
        :rtype: list

        """
        log = []
        if c_reg.search(self.contenu[noligne]):
            match = c_reg.match(self.contenu[noligne])
            log_tuple = match.groups('default')
            log = list(log_tuple)

        """
        ip = log[0]
        idclient (name) = log[1]
        auth = log[2]
        date = log[3]
        request (URL) = log[4]
        status (Response) = log[5]
        size = log[6]
        referer (Optional) = log[7]
        agent (Optional) = log[8]

        """

        return log


class FichierRegExp(Fichier):
    """
    Classe instanciant des fichiers d'expressions régulières caractérisé par :

    - son nombre de ligne
    - son contenu
    - son chemin d'accès
    - si il est read-only ou non

    """

    def __init__(self, filepath):
        super(FichierRegExp, self).__init__(filepath)
        self.doc = Etree.parse(filepath).getroot()

    def lireligne(self, noligne):
        super(FichierRegExp, self).lireligne(noligne)

    def fermerfichier(self):
        super(FichierRegExp, self).fermerfichier()

    def decouperligne(self, noligne):
        """
        Decoupage syntaxique de la n-ieme ligne pour récupérer les regExp

        :param noligne: Numéro de ligne
        :type noligne: int
        :return: Liste contenant les différents champs découpés.
        :rtype: list

        """
        return [int(self.doc[noligne][0].text), self.doc[noligne][1].text,
                self.doc[noligne][2].text, int(self.doc[noligne][4].text)]


class FichierRapportTextuel(Fichier):
    """Classe instanciant le rapport textuel caractérisé par :

    - son nombre de ligne
    - son contenu
    - son chemin d'accès
    - si il est read-only ou non

    """
    def __init__(self, filepath):
        """
        Constructeur de classe. Un fichier est initialisé à partir de son chemin d'accès

        :param filepath: chemin d'accès du fichier
        :type filepath: str

        """
        self.file = open(filepath, 'w')
        self.chemin = filepath
        self.contenu = []
        self.nbLigne = 0
        self.ro = False

    def lireligne(self, noligne):
        super(FichierRapportTextuel, self).lireligne(noligne)

    def fermerfichier(self):
        super(FichierRapportTextuel, self).fermerfichier()

    def ecriretexte(self, data):
        """
        Ecrit les lignes en entrée à la fin du fichier

        :param data: numero de la ligne voulu
        :type data: list

        """
        for ligne in data:
            self.file.write(ligne + "\n")
            self.nbLigne += 1
            self.contenu.append(ligne)
        return
