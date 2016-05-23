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
            L.append(self.format_byte(stat["Bandwidth"][i]) + "\t\t" + str(stat["Hits"][i]) + "\t" + str(stat["Visitors"][i]) + "\t\t" + str(stat["Method"][i]) + "\t" + str(stat["URL"][i]) )
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
            L.append(self.format_byte(stat["Bandwidth"][i]) + "\t\t" + str(stat["Hits"][i]) + "\t" + str(stat["Visitors"][i]) + "\t\t" + str(stat["Method"][i]) + "\t" + str(stat["Referrer"][i]) )
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
            L.append(self.format_byte(stat["Bandwidth"][i]) + "\t\t" + str(stat["Hits"][i]) + "\t" + str(stat["Visits"][i]) + "\t" + str(stat["IP"][i]))
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
        L.append(">> ORDERED BY NUMBER OF HITS THEN BY IMPACT (DESC) >>")
        L.append("   -----------------------------------------------\n\n")
        for url, e in L2[:5]:
            L.append("URL " + str(url) + "\n\t" + "Impact\t\t" + str(e[2]) + "\n\tDescription\t" + str(e[1]) + "\n\tHits\t\t" + str(len(e[0])) + "\n\tLogLineNumbers\t" + ", ".join(e[0]) + "\n\n")
        L3 = sorted(d.items(), key=lambda e: (-e[1][2], -len(e[1][0])))
        L.append(">> ORDERED BY IMPACT THEN BY NUMBER OF HITS (DESC) >>")
        L.append("   -----------------------------------------------\n\n")
        for url, e in L3[:5]:
            L.append("URL " + str(url) + "\n\t" + "Impact\t\t" + str(e[2]) + "\n\tDescription\t" + str(e[1]) + "\n\tHits\t\t" + str(len(e[0])) + "\n\tLogLineNumbers\t" + ", ".join(e[0]) + "\n\n")
        return L
        
    def format_byte(self, byte):
        if int(byte) > 1000000000:
            byte = str(int(byte)//1000000000) + " Go"
        elif int(byte) > 1000000:
            byte = str(int(byte)//1000000) + " Mo"
        elif int(byte) > 1000:
            byte = str(int(byte)//1000) + " Ko"
        return str(byte)

    
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
            report.append("\n\n========================== \033[98mStats\033[0m ==========================\n")
            report.append("\n\n========================== \033[97mStats\033[0m ==========================\n")
            report.append("\n\n========================== \033[96mStats\033[0m ==========================\n")
            report.append("\n\n========================== \033[95mStats\033[0m ==========================\n")
            report.append("\n\n========================== \033[94mStats\033[0m ==========================\n")
            report.append("\n\n========================== \033[92mStats\033[0m ==========================\n")
            report.append("\n\n========================== \033[93mStats\033[0m ==========================\n")
            report.append("\n\n========================== \033[91mStats\033[0m ==========================\n")
            report.append("\n\n========================== \033[1mStats\033[0m ==========================\n")
            report.append("\n\n========================== \033[6mStats\033[0m ==========================\n")
            report.append("\n\n========================== \033[30mStats\033[0m ==========================\n")
            report.append("\n\n========================== \033[36mStats\033[0m ==========================\n")
            report.append("\n\n========================== \033[41mStats\033[0m ==========================\n")
            stat_keys = self.stat_dict.keys()
            for key in stat_keys:
                stat = self.stat_dict[key]
                if type(stat) == int:
                    report.append(str(key) + "\t " + str(stat))
            for key in stat_keys:
                stat = self.stat_dict[key]
                if type(stat) != int:
                    if str(key) == "TopFiles":
                        topfiles = self.get_topfiles(stat)
                        report.append("\n>> TOP FILES >>\n")
                        report.append("Bandwidth\tHits\tVisitors\tMethod\tURL")
                        report.append("---------\t----\t--------\t------\t---")
                        for ligne in topfiles:
                            report.append(ligne)
                        report.append("")
                    elif str(key) == "TopReferrers":
                        topreferrers = self.get_topreferrers(stat)
                        report.append("\n>> TOP REFERRERS >>\n")
                        report.append("Bandwidth\tHits\tVisitors\tMethod\tReferrer")
                        report.append("---------\t----\t--------\t------\t--------")
                        for ligne in topreferrers:
                            report.append(ligne)
                        report.append("")
                    elif str(key) == "TopVisitors":
                        topvisitors = self.get_topvisitors(stat)
                        report.append("\n>> TOP VISITORS >>\n")
                        report.append("Bandwidth\tHits\tVisits\tIP")
                        report.append("---------\t----\t------\t--")
                        for ligne in topvisitors:
                            report.append(ligne)
                        report.append("")
                    else:
                        report.append(str(key) + " ------->" + str(stat))
            report.append("\n\n========================== WARNING ==========================\n")
            attack = self.attack_dict
            attacks = self.get_attack(attack)
            for ligne in attacks:
                report.append(ligne)
        return report
