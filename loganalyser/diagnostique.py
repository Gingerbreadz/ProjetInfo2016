"""
Implementation du Diagnostique.
Il reste à écrire les méthode d'analyse et de statistique.
TODO: Ecrire la méthode qui génère le rapport. | Reste plus tard.
"""

from loganalyser import token   #Gestion des tokens
from loganalyser import outils  #Gestion des Dictionnaires

class Diagnostique:
    """Classe instanciant le diagnostique, qui contient les résultats d'analyse et les fait.
    """

    def __init__(self, token_dictionary, regexp_dictionary):
        """
        Constructeur de classe. Un diagnostique est initialisé à partir de tokens.

        :param token_dictionary: dictionnaire de token
        :type token_dictionary: dict
        :param regexp_dictionary: dictionnaire de regexp
        :type regexp_dictionary: dict

        """

        self.token_dict = token_dictionary
        self.regexp_dict = regexp_dictionary
        self.stat_dict = {}
        self.attack_dict = {}
        self.__statistique()
        self.__analyse_multitoken()
        return

    def __statistique(self):
        """
        Effectue des calculs statistiques sur les token.

        :param token_dict: dictionnaire de token
        :type token_dict: dict
        :return: Dictionnaire contenant les statistiques
        :rtype: dict

        """
        self.stat_dict = {}
        return

    def __analyse_multitoken(self):
        """
        Analyse les tokens par groupe selon certains motifs.

        :param token_dict: dictionnaire de token
        :param regexp_dict: dictionnaire d'expression régulière
        :type token_dict: dict
        :type regexp_dict: dict
        :return: Dictionnaire contenant le rapport des attaques subit
        :rtype: dict

        """
        self.attack_dict = {}
        return

    def get_report(self, fileformat):
        """
        Ordonne les donnée issues des statistiques et des analyses, prépare pour l'affichage finale.

        :param fileformat: indique si le rapport doit etre enregistré sous forme de fchier texte ou seulement être présenté dans la console
        :type fileformat: bool
        :return: tableau des lignes de résultats à partir des dictionnaires
        :rtype: String array

        """
        if fileformat:
            report = ["Ceci est la première ligne du Fichier Rapport", "Ceci est la deuxième"]
        else:
            report=["                         ===Stats===                       "]
            L=[]
            Stat_keys=self.stat_dict.keys()
            for skey in Stat_keys: #Stock les clé correspondant aux différents types de stats
                stat=self.stat_dict[skey] #Stock le dictionnaire correspondant à un type de stat dans la varaible 
                report=report.append(skey)  # on affichera le clé si celle-ci correspond au nom de la stat
                for key in stat.keys():
                    L.append(key, stat[key]) #on affiche chaque champ de la stat 
                    report=report+L
        return report


