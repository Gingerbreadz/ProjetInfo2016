"""
Module token
Il reste à écrire pour chacun des types de token les méthodes de vérification et de calcul de la sévérité.
TODO: Implementer tests type log; Calculs de sévérité | Reste rien.
"""
import socket
    

from abc import ABCMeta, abstractmethod


class Token:
    """
    Classe abstraite interface pour token caractérisé par :

    - sa donnée
    - sa sévérité

    """
    __metaclass__ = ABCMeta

    def __init__(self, value):
        """
        Constructeur de classe. Un fichier est initialisé à partir de son chemin d'accès

        :param value: donnee du token e.g. "127.0.0.1", "404".
        :type value: str

        """
        if self.__verifier_type:
            self.donnee = value
            self.severite = self.__analyse()
        else:
            raise ValueError("Mauvais type de donnee")
        return

    @abstractmethod
    def __verifier_type(self):
        """
        Vérifie si la donnee peut bien être instanciée sous cette classe de Token.

        :return: Retourne la réponse de la vérification
        :rtype: bool

        """
        return

    @abstractmethod
    def __analyse(self):
        """
        Analyse la donnee contenue dans le token pour obtenir la sévérité de cette donnee.

        :return: Retourne la sévérité de la donnee de ce token
        :rtype: int

        """
        return


class IP(Token):
    """Classe concrète instanciant les token IP"""
  
    def __verifier_type(self):
        try:
            socket.inet_pton(socket.AF_INET, self)  # "verifie" que l'ip est une ip (ipv4)
        except socket.error: 
            try :
                socket.inet_pton(socket.AF_INET6, self)  # "verifie" que l'ip est une ip (ipv6)
            except socket.error:
                return False
        return True
                        
    def __analyse(self):
        severity_level = 0
        return severity_level


class Name(Token):
    """Classe concrète instanciant les token Nom"""

    def __verifier_type(self):
        s = True
        return s

    def __analyse(self):
        severity_level = 0
        return severity_level


class Date(Token):
    """Classe concrète instanciant les token Date"""

    def __verifier_type(self):
        s = True
        return s

    def __analyse(self):
        severity_level = 0
        return severity_level


class EXT(Token):
    """Classe concrète instanciant les token Ext"""

    def __verifier_type(self):
        s = True
        return s

    def __analyse(self):
        severity_level = 0
        return severity_level


class Methode(Token):
    """Classe concrète instanciant les token Methode"""

    def __verifier_type(self):
        s = ["GET", "HEAD", "POST", "OPTIONS", "CONNECT", "TRACE", "PUT", "DELETE"]
        self.upper()
        if self in s:
            return True
        else: 
            return False

    def __analyse(self):
        severity_level = 0
        return severity_level


class URL(Token):
    """Classe concrète instanciant les token URL"""

    def __verifier_type(self):
        s = True
        return s

    def __analyse(self):
        severity_level = 0
        return severity_level


class Response(Token):
    """Classe concrète instanciant les token Réponse"""

    def __verifier_type(self):
        s = True
        return s

    def __analyse(self):
        severity_level = 0
        return severity_level


class Byte(Token):
    """Classe concrète instanciant les token Octet"""

    def __verifier_type(self):
        try:
            int(self)
        except:
            return False
        return True
            

    def __analyse(self):
        severity_level = 0
        return severity_level


class Referer(Token):
    """Classe concrète instanciant les token Referer"""

    def __verifier_type(self):
        s = True
        return s

    def __analyse(self):
        severity_level = 0
        return severity_level
