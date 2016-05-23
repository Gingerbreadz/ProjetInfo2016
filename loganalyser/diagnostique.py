"""
Implementation du Diagnostique.
"""

from loganalyser import outils  # Gestion des Dictionnaires
import re


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
        self.__analyse()
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

        def uniquevisitors():
            ip_list = [ip.donnee for ip in self.token_dict["IP"]]
            ip_distinct_list = list(set(ip_list))
            return len(ip_distinct_list)

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
                byte_count = 0
                visitors = 0
                for j in lines:
                    byte_count += byte_list[j]
                    if ip_list[j] not in counted_ip:
                        counted_ip.append(ip_list[j])
                        visitors += 1
                topfiles_dic.addentry([url_list.count(url), visitors, byte_count, method_list[i], url])
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
                byte_count = 0
                visitors = 0
                for j in lines:
                    byte_count += byte_list[j]
                    if ip_list[j] not in counted_ip:
                        counted_ip.append(ip_list[j])
                        visitors += 1
                topreferrers_dic.addentry([referrer, referrer_list.count(referrer), visitors, byte_count, method_list[i]])
            return topreferrers_dic

        def topvisitors():
            topvisitors_dic = outils.Dictionary(["Hits", "Visits", "Bandwidth", "IP"])
            ip_list = [ip.donnee for ip in self.token_dict["IP"]]
            byte_list = [int(byte.donnee) for byte in self.token_dict["Byte"]]
            url_list = [url.url_cut for url in self.token_dict["URL"]]
            ip_distinct_list = list(set(ip_list))
            for i in range(0, len(ip_distinct_list)):
                ip = ip_distinct_list[i]
                lines = self.token_dict.itemtoentrynumbers(ip)
                counted_url = []
                byte_count = 0
                visitors = 0
                for j in lines:
                    byte_count += byte_list[j]
                    if url_list[j] not in counted_url:
                        counted_url.append(url_list[j])
                        visitors += 1
                topvisitors_dic.addentry([ip_list.count(ip), visitors, byte_count, ip])
            return topvisitors_dic

        self.stat_dict["UniqueVisitors"] = uniquevisitors()  # Int
        self.stat_dict["TotalVisitors"] = totalvisitors()    # Int
        self.stat_dict["TopFiles"] = topfiles()              # SubDict:["Hits", "Visitors", "Bandwidth", "Method", "URL"]
        self.stat_dict["TopReferrers"] = topreferrers()      # SubDict:["Referrer", "Hits", "Visitors", "Bandwidth", "Method"]
        self.stat_dict["TopVisitors"] = topvisitors()        # SubDict:["Hits", "Visits", "Bandwidth", "IP"]
        self.stat_dict["ValidRequest"] = validrequest()      # Int
        self.stat_dict["NotFoundURL"] = notfoundurl()        # Int

    def __analyse(self):
        """
        Analyse les tokens par groupe selon certains motifs.

        :param self.token_dict: dictionnaire de token
        :param self.regexp_dict: dictionnaire d'expression régulière
        :type self.token_dict: dict
        :type self.regexp_dict: dict
        :return: Dictionnaire contenant le rapport des attaques subit
        :rtype: dict

        """
        self.attack_dict = outils.Dictionary(["LogLineNumber", "URL", "Description", "Impact"])
        url_list = [url.donnee for url in self.token_dict["URL"]]
        for i in range(0, len(self.regexp_dict["Number"])):
            rule = self.regexp_dict["Rule"][i]
            rule_reg = re.compile(rule)
            for j in range(0, len(url_list)):
                url = url_list[j]
                if rule_reg.search(url):
                    self.attack_dict["LogLineNumber"] += [j]
                    self.attack_dict["URL"] += [url]
                    self.attack_dict["Description"] += [self.regexp_dict["Description"][i]]
                    self.attack_dict["Impact"] += [self.regexp_dict["Impact"][i]]

    def get_indices_top(self, liste):
        indices = [0] * 5
        valeurs = [liste[0]] * 5
        for i in range(len(liste)):
            if liste[i] > min(valeurs):
                ind = valeurs.index(min(valeurs))
                indices[ind] = i
                valeurs[ind] = liste[i]
        valeurs, indices = (list(t) for t in zip(*sorted(zip(valeurs, indices), reverse=True)))
        return indices
    
    def get_topfiles(self, stat):
        """
        ordonne la liste des top files et s'assure de sa configuration afin d'obtenir un affichage lisible des résultats
        :param stat: dictionnaire de statistiques
        :param n: nombre de données souhaitées
        :type stats: dict
        :type n: int
        :return: Liste des strings organisées.
        :rtype: list
        
        """
        indices = self.get_indices_top(stat["Hits"])
        L = []
        for i in indices:
            L.append("\033[36m" + self.format_byte(stat["Bandwidth"][i]) + "\033[0m\t\t\033[91m" + str(stat["Hits"][i]) + "\033[0m\t\033[92m" + str(stat["Visitors"][i]) + "\033[0m\t\t\033[97m" + str(stat["Method"][i]) + "\033[0m\t\033[35m" + str(stat["URL"][i]) + "\033[0m" )
        return L
        
    def get_topreferrers(self, stat):
        """
        ordonne la liste des top referrers et s'assure de sa configuration afin d'obtenir un affichage lisible des résultats
        :param stat: dictionnaire de statistiques
        :param n: nombre de données souhaitées
        :type stats: dict
        :type n: int
        :return: Liste des strings organisées.
        :rtype: list
        
        """
        indices = self.get_indices_top(stat["Hits"])
        L = []
        for i in indices:
            L.append("\033[36m" + self.format_byte(stat["Bandwidth"][i]) + "\033[0m\t\t\033[91m" + str(stat["Hits"][i]) + "\033[0m\t\033[092m" + str(stat["Visitors"][i]) + "\033[0m\t\t\033[97m" + str(stat["Method"][i]) + "\033[0m\t\033[35m" + str(stat["Referrer"][i]) + "\033[0m" )
        return L
        
    def get_topvisitors(self, stat):
        """
        ordonne la liste des top visitors et s'assure de sa configuration afin d'obtenir un affichage lisible des résultats
        :param stat: dictionnaire de statistiques
        :param n: nombre de données souhaitées
        :type stats: dict
        :type n: int
        :return: Liste des strings organisées.
        :rtype: list
        
        """
        indices = self.get_indices_top(stat["Hits"])
        L = []
        for i in indices:
            L.append("\033[36m" + self.format_byte(stat["Bandwidth"][i]) + "\033[0m\t\t\033[91m" + str(stat["Hits"][i]) + "\033[0m\t\033[92m" + str(stat["Visits"][i]) + "\033[0m\t\033[97m" + str(stat["IP"][i]) + "\033[0m")
        return L
        
    def get_attack(self, attack):
        """
        ordonne la liste des potentiels attaques et s'assure de sa configuration afin d'obtenir un affichage lisible des résultats
        :param stat: dictionnaire de statistiques
        :param n: nombre de données souhaitées
        :type stats: dict
        :type n: int
        :return: Liste des strings organisées.
        :rtype: list
        
        """
        d = {}
        for i in range(len(attack["URL"])):
            url = attack["URL"][i]
            if url in d:
                d[url][0].append(str(attack["LogLineNumber"][i]))
            else:
                d[url] = [ [str(attack["LogLineNumber"][i])], attack["Description"][i], attack["Impact"][i]]
        for key, elt in d.items():
            d[key][0] = list(set(elt[0]))
        L = []
        L2 = sorted(d.items(), key=lambda e: (-len(e[1][0]), -e[1][2])) # tri le dictionnaire en fonction du nombre d'apparition décroissant (d'ou le signe negatif)
        L.append("\n\033[100m\033[97m\033[1m   4 - DANGER - order by number of hits, then by impact (desc)\t\t\t\t\t\t\033[0m\n")
        for url, e in L2[:5]:
            L.append("\033[36mURL\033[0m\033[35m " + str(url) + "\033[0m\n\t" + "\033[36mImpact\033[0m\t\t" + str(e[2]) + "\n\t\033[36mDescription\033[0m\t" + str(e[1]) + "\n\t\033[36mHits\033[0m\t\t" + str(len(e[0])) + "\n\t\033[36mLogLineNumbers\033[0m\t" + ", ".join(e[0]) + "\n\n")
        L3 = sorted(d.items(), key=lambda e: (-e[1][2], -len(e[1][0])))
        L.append("\n\033[100m\033[97m\033[1m   4 - DANGER - order by impact, then by number of hits (desc)\t\t\t\t\t\t\033[0m\n")
        for url, e in L3[:5]:
            L.append("\033[36mURL\033[0m\033[035m " + str(url) + "\033[0m\n\t" + "\033[36mImpact\033[0m\t\t" + str(e[2]) + "\n\t\033[36mDescription\033[0m\t" + str(e[1]) + "\n\\033[36mHits\033[0m\t\t" + str(len(e[0])) + "\n\t\033[36mLogLineNumbers\033[0m\t" + ", ".join(e[0]) + "\n\n")
        return L
        
    def format_byte(self, byte):
        if int(byte) > 1000000000:
            byte = str(int(byte)//1000000000) + " Go"
        elif int(byte) > 1000000:
            byte = str(int(byte)//1000000) + " Mo"
        elif int(byte) > 1000:
            byte = str(int(byte)//1000) + " Ko"
        else:
            byte = str(byte) + " o"
        return byte

    
    def get_report(self, fileformat):
        """
        Ordonne les donnée issues des statistiques et des analyses, prépare pour l'affichage finale.

        :param fileformat: indique si le rapport doit etre enregistré sous forme de fchier texte ou seulement être présenté dans la console
        :type fileformat: bool
        :return: tableau des lignes de résultats à partir des dictionnaires
        :rtype: list

        """
        if fileformat:
            report = ["Ceci est la première ligne du Fichier Rapport", "Ceci est la deuxième"]
        else:
            report = list()
            report.append("\n\n\033[100m\033[97m\033[1m   Analyse générale du fonctionnement\t\t\t\t\033[0m\n")
            stat_keys = self.stat_dict.keys()
            for key in stat_keys:
                stat = self.stat_dict[key]
                if type(stat) == int:
                    report.append("\t\033[97m" + str(key) + "\033[0m\033[92m\t " + str(stat) + "\033[0m")
            for key in stat_keys:
                stat = self.stat_dict[key]
                if type(stat) != int:
                    if str(key) == "TopFiles":
                        topfiles = self.get_topfiles(stat)
                        report.append("\n\033[100m\033[97m\033[1m   1 - TOP FILES\t\t\t\t\t\t\033[0m\n")
                        report.append("\033[37mBandwidth\tHits\tVisitors\tMethod\tURL")
                        report.append("---------\t----\t--------\t------\t---\033[0m")
                        for ligne in topfiles:
                            report.append(ligne)
                        report.append("")
                    elif str(key) == "TopReferrers":
                        topreferrers = self.get_topreferrers(stat)
                        report.append("\n\033[100m\033[97m\033[1m   2 - TOP REFERRERS\t\t\t\t\t\t\033[0m\n")
                        report.append("\033[37mBandwidth\tHits\tVisitors\tMethod\tReferrer")
                        report.append("---------\t----\t--------\t------\t--------\033[0m")
                        for ligne in topreferrers:
                            report.append(ligne)
                        report.append("")
                    elif str(key) == "TopVisitors":
                        topvisitors = self.get_topvisitors(stat)
                        report.append("\n\033[100m\033[97m\033[1m   3 - TOP VISITORS\t\t\t\t\t\t\033[0m\n")
                        report.append("\033[37mBandwidth\tHits\tVisits\tIP")
                        report.append("---------\t----\t------\t--\033[0m")
                        for ligne in topvisitors:
                            report.append(ligne)
                        report.append("")
                    else:
                        report.append(str(key) + " ------->" + str(stat))
            attack = self.attack_dict
            attacks = self.get_attack(attack)
            for ligne in attacks:
                report.append(ligne)
        return report
