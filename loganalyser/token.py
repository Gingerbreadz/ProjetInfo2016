"""
Module token
Ce sont les classes qui sont utilisés pour caractériser les différents champs de log.
"""
import socket
import re
#from urllib.parse import urlparse
from datetime import datetime

from abc import ABCMeta, abstractmethod


class Token:
    """
    Classe abstraite interface pour token caractérisé par :
    - sa donnée
    - sa sévérité
    """
    __metaclass__ = ABCMeta

    def __init__(self, value, istypeok):
        """
        Constructeur de classe. Un fichier est initialisé à partir de son chemin d'accès

        :param value: donnee du token e.g. "127.0.0.1", "404".
        :type value: str

        """
        if istypeok:
            self.donnee = value
            self.severite = self.__analyse()
        else:
            raise ValueError("Mauvais type de donnee")

    @abstractmethod
    def __verifier_type(self, value):
        """
        Vérifie si la donnee peut bien être instanciée sous cette classe de Token.

        :return: Retourne la réponse de la vérification
        :rtype: bool

        """

    @abstractmethod
    def __analyse(self):
        """
        Analyse la donnee contenue dans le token pour obtenir la sévérité de cette donnee. Non implémenté car non-utile.

        :return: Retourne la sévérité de la donnee de ce token
        :rtype: int

        """


class IP(Token):
    """Classe concrète instanciant les token IP"""
    def __init__(self, value):
        super().__init__(value, self.__verifier_type(value))

    def __verifier_type(self, value):
        try:
            socket.inet_pton(socket.AF_INET, value)  # "verifie" que l'ip est une ip (ipv4)
        except socket.error: 
            try:
                socket.inet_pton(socket.AF_INET6, value)  # "verifie" que l'ip est une ip (ipv6)
            except socket.error:
                return False
        return True
                        
    def __analyse(self):
        severity_level = 0
        return severity_level


class Name(Token):
    """Classe concrète instanciant les token Nom"""
    def __init__(self, value):
        super().__init__(value, self.__verifier_type(value))

    def __verifier_type(self, value):
        return type(value) == str

    def __analyse(self):
        severity_level = 0
        return severity_level


class Date(Token):
    """Classe concrète instanciant les token Date"""

    def __init__(self, value):
        super().__init__(value, self.__verifier_type(value))

    def __verifier_type(self, value):
        try:
            datetime.strptime(value, '%d/%b/%Y:%H:%M:%S')
        except ValueError:
            return False
        else:
            return True

    def __analyse(self):
        severity_level = 0
        return severity_level


class EXT(Token):
    """Classe concrète instanciant les token Ext"""
    def __init__(self, value):
        super().__init__(value, self.__verifier_type(value))

    def __verifier_type(self, value):
        try:
            int(value)
        except ValueError:
            return False
        return True

    def __analyse(self):
        severity_level = 0
        return severity_level


class Method(Token):
    """Classe concrète instanciant les token Methode"""
    def __init__(self, value):
        super().__init__(value, self.__verifier_type(value))

    def __verifier_type(self, value):
        s = ["GET", "HEAD", "POST", "OPTIONS", "CONNECT", "TRACE", "PUT", "DELETE"]
        return value in s

    def __analyse(self):
        severity_level = 0
        return severity_level


class URL(Token):
    """Classe concrète instanciant les token URL"""
    def __init__(self, value):
        url_cut_reg = re.compile("^([^?]*)(.*)$")
        self.url_cut = list(url_cut_reg.match(value).groups('defaults'))[0]
        super().__init__(value, self.__verifier_type(value))

    def __verifier_type(self, value):
        return type(value) == str

    def __analyse(self):
        severity_level = 0
        return severity_level

    """def normalisation(self):
        url_reg = re.compile('([^ ]*) ([^ ]*) ([^ ]*)')
        tab = url_reg.match(self.donnee).groups('default')
        url = urlparse(tab[1])
        return url"""


class Response(Token):
    """Classe concrète instanciant les token Réponse"""
    def __init__(self, value):
        super().__init__(value, self.__verifier_type(value))

    def __verifier_type(self, value):
        try:
            int(value)
        except ValueError:
            return False
        return 99 < int(value) < 600

    def __analyse(self):
        severity_level = 0
        return severity_level


class Byte(Token):
    """Classe concrète instanciant les token Octet"""
    def __init__(self, value):
        super().__init__(value, self.__verifier_type(value))

    def __verifier_type(self, value):
        try:
            int(value)
        except ValueError:
            return False
        return True

    def __analyse(self):
        severity_level = 0
        return severity_level


class Referer(Token):
    """Classe concrète instanciant les token Referer"""
    def __init__(self, value):
        url_cut_reg = re.compile("^(.*[/]{2}[w]?[w]?[w]?[.]?)(\w*[.]\w*)(.*)$")
        self.domain = value
        if url_cut_reg.search(value):
            self.domain = list(url_cut_reg.match(value).groups('defaults'))[2]
        super().__init__(value, self.__verifier_type(value))

    def __verifier_type(self, value):
        return type(value) == str

    def __analyse(self):
        severity_level = 0
        return severity_level
