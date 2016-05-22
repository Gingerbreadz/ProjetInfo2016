"""
Implementation du Diagnostique.
Il reste à écrire les méthode d'analyse et de statistique.
TODO: Ecrire la méthode qui génère le rapport. | Reste plus tard.
"""

from loganalyser import outils  # Gestion des Dictionnaires


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

        :param self.token_dict: dictionnaire de token
        :type self.token_dict: dict
        :return: Dictionnaire contenant les statistiques
        :rtype: dict

        """
        self.stat_dict = outils.Dictionary(["UniqueVisitors", "TotalVisitors", "TopFiles", "TopReferrers",
                                            "TopVisitors", "ValidRequest", "NotFoundURL"])

        def uniquevisitors(): return len(list(set(self.token_dict["IP"])))

        def totalvisitors(): return len(self.token_dict["IP"])

        def validrequest():
            code_list = self.token_dict["Response"]
            url_list = self.token_dict["URL"]
            counted_url = []
            s = 0
            for i in range(0, len(code_list)):
                if 200 <= int(code_list[i].donnee) <= 226 and url_list[i].donnee not in counted_url:
                    counted_url.append(url_list[i].donnee)
                    s += 1
            return s

        def notfoundurl():
            code_list = self.token_dict["Response"]
            ip_list = self.token_dict["IP"]
            counted_ip = []
            s = 0
            for i in range(0, len(code_list)):
                if int(code_list[i].donnee) == 404 and ip_list[i].donnee not in counted_ip:
                    counted_ip.append(ip_list[i].donnee)
                    s += 1
            return s

        def topfiles():
            url_list = [url.donnee for url in self.token_dict["URL"]]
            ip_list = [ip.donnee for ip in self.token_dict["IP"]]
            method_list = [method.donnee for method in self.token_dict["Method"]]
            byte_list = [int(byte.donnee) for byte in self.token_dict["Byte"]]
            url_distinct_list = list(set(url_list))
            topfiles_dic = outils.Dictionary(["Hits", "Visitors", "Bandwidth", "Method", "URL"])
            for i in range(0, len(url_distinct_list)):
                url = url_distinct_list[i]
                lines = self.token_dict.itemtoentrynumbers(url)
                counted_ip = []
                topfiles_dic["Hits"][i] = url_list.count(url)
                topfiles_dic["Method"][i] = method_list[i]
                topfiles_dic["URL"][i] = url
                for j in lines:
                    topfiles_dic["Bandwidth"][i] += byte_list[j]
                    if ip_list[j] not in counted_ip:
                        counted_ip.append(ip_list[j])
                        topfiles_dic["Visitors"][i] += 1
            return topfiles_dic

        def topreferrers():
            referrer_list = [referrer.donnee for referrer in self.token_dict["Referrer"]]
            ip_list = [ip.donnee for ip in self.token_dict["IP"]]
            method_list = [method.donnee for method in self.token_dict["Method"]]
            byte_list = [int(byte.donnee) for byte in self.token_dict["Byte"]]
            referrer_distinct_list = list(set(referrer_list))
            topreferrers_dic = outils.Dictionary(["Referrer", "Hits", "Visitors", "Bandwidth", "Method"])
            for i in range(0, len(referrer_distinct_list)):
                referrer = referrer_distinct_list[i]
                lines = self.token_dict.itemtoentrynumbers(referrer)
                counted_ip = []
                topreferrers_dic["Referrer"][i] = referrer
                topreferrers_dic["Method"][i] = method_list[i]
                topreferrers_dic["Hits"][i] = referrer_list.count(referrer)
                for j in lines:
                    topreferrers_dic["Bandwidth"][i] += byte_list[j]
                    if ip_list[j] not in counted_ip:
                        counted_ip.append(ip_list[j])
                        topreferrers_dic["Visitors"][i] += 1
            return topreferrers_dic

        def topvisitors():
            topvisitors_dic = outils.Dictionary(["Hits", "Visits", "Bandwidth", "IP"])
            ip_list = [ip.donnee for ip in self.token_dict["IP"]]
            byte_list = [int(byte.donnee) for byte in self.token_dict["Byte"]]
            url_list = [url.donnee for url in self.token_dict["URL"]]
            ip_distinct_list = list(set(ip_list))
            for i in range(0, len(ip_distinct_list)):
                ip = ip_distinct_list[i]
                lines = self.token_dict.itemtoentrynumbers(ip)
                counted_url = []
                topvisitors_dic["Hits"][i] = ip_list.count(ip)
                topvisitors_dic["IP"][i] = ip
                for j in lines:
                    topvisitors_dic["Bandwidth"][i] += byte_list[j]
                    if url_list[j] not in counted_url:
                        counted_url.append(url_list[j])
                        topvisitors_dic["Visits"][i] += 1
            return topvisitors_dic

        self.stat_dict["UniqueVisitors"] = uniquevisitors()  # Int
        self.stat_dict["TotalVisitors"] = totalvisitors()    # Int
        self.stat_dict["TopFiles"] = topfiles()              # SubDict:["Hits", "Visitors", "Bandwidth", "Method", "URL"]
        self.stat_dict["TopReferrers"] = topreferrers()      # SubDict:["Referrer", "Hits", "Visitors", "Bandwidth", "Method"]
        self.stat_dict["TopVisitors"] = topvisitors()        # SubDict:["Hits", "Visits", "Bandwidth", "IP"]
        self.stat_dict["ValidRequest"] = validrequest()      # Int
        self.stat_dict["NotFoundURL"] = notfoundurl()        # Int

    def __analyse_multitoken(self):
        """
        Analyse les tokens par groupe selon certains motifs.

        :param self.token_dict: dictionnaire de token
        :param self.regexp_dict: dictionnaire d'expression régulière
        :type self.token_dict: dict
        :type self.regexp_dict: dict
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


