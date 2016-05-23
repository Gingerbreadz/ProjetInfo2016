"""
Implementation du Diagnostique.
"""

from loganalyser import outils  # Gestion des Dictionnaires
import re
import time

class Diagnostique:
    """Classe instanciant le diagnostique, qui contient les résultats d'analyse et les fait.
    """

    def __init__(self, token_dictionary, regexp_dictionary, n=5, nomatchcount=0):
        """
        Constructeur de classe. Un diagnostique est initialisé à partir de tokens.

        :param token_dictionary: dictionnaire de token
        :type token_dictionary: dict
        :param regexp_dictionary: dictionnaire de regexp
        :type regexp_dictionary: dict
        :param n: nombre de ligne à afficher (5 par défaut)
        :type n: int
        :param nomatchcount: nombre de ligne n'ayant pas matchés (0 par défaut)
        :type nomatchcount: int

        """
        self.nomatchcount = nomatchcount
        self.line = n
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
                                            "TopVisitors", "ValidRequest", "NotFoundURL", "TopUniqueResponses"])

        def uniquevisitors():
            """
            détermine le nombre de visiteurs uniques total.
            
            :return: nombre de visiteurs
            :rtype: int

            """
            ip_list = [ip.donnee for ip in self.token_dict["IP"]]
            ip_distinct_list = list(set(ip_list))
            return len(ip_distinct_list)

        def totalvisitors():
            """
            détermine le nombre de visites total.
            
            :return: nombre de visites
            :rtype: int

            """
            return len(self.token_dict["IP"])

        def validrequest():
            """
            détermine le nombre requêtes ayant correctement abouties.
            
            :return: nombre de requêtes 
            :rtype: int

            """
            if "NoMatch" in self.token_dict.keys():
                return totalvisitors() - self.nomatchcount
            else:
                return totalvisitors()

        def topuniqueresponses():
            """
            détermine le nombre de réponses associées aux série des codes erreurs
            
            :return: dictionnaire des données en rapport avec les codes erreurs de retour du serveur
            :rtype: dict

            """
            code_list = self.token_dict["Response"]
            url_list = self.token_dict["URL"]
            byte_list = [int(byte.donnee) for byte in self.token_dict["Byte"]]
            counted_url2, counted_url3, counted_url4, counted_url5 = [], [], [], []
            s2, s3, s4, s5 = 3*[0], 3*[0], 3*[0], 3*[0]
            for i in range(0, len(code_list)):
                code = int(code_list[i].donnee)
                url = url_list[i].donnee
                if 200 <= code <= 226:
                    s2[0] += 1
                    s2[2] += byte_list[i]
                    if url not in counted_url2:
                        counted_url2.append(url_list[i].donnee)
                        s2[1] += 1
                elif 300 <= code <= 310:
                    s3[0] += 1
                    s3[2] += byte_list[i]
                    if url not in counted_url3:
                        counted_url3.append(url_list[i].donnee)
                        s3[1] += 1
                elif 400 <= code <= 499:
                    s4[0] += 1
                    s4[2] += byte_list[i]
                    if url not in counted_url4:
                        counted_url4.append(url_list[i].donnee)
                        s4[1] += 1
                elif 500 <= code <= 520:
                    s5[0] += 1
                    s5[2] += byte_list[i]
                    if url not in counted_url5:
                        counted_url5.append(url_list[i].donnee)
                        s5[1] += 1

            topuniquereponses_dic = outils.Dictionary(["Hits", "Visitors", "Bandwidth", "Code"])
            topuniquereponses_dic.addentry([s2[0], s2[1], s2[2], "2xx Success"])
            topuniquereponses_dic.addentry([s3[0], s3[1], s3[2], "3xx Redirection"])
            topuniquereponses_dic.addentry([s4[0], s4[1], s4[2], "4xx Client Error"])
            topuniquereponses_dic.addentry([s5[0], s5[1], s5[2], "5xx Server Error"])
            return topuniquereponses_dic

        def notfoundurl():
            """
            détermine le nombre de requêtes ayant abouties à un code erreur 404 "URL not found".
            
            :return: nombre de requêtes
            :rtype: int

            """
            code_list = self.token_dict["Response"]
            url_list = self.token_dict["URL"]
            counted_url = []
            s = 0
            for i in range(0, len(code_list)):
                if int(code_list[i].donnee) == 404 and url_list[i].url_cut not in counted_url:
                    counted_url.append(url_list[i].url_cut)
                    s += 1
            return s

        def topfiles():
            """
            détermine les données liés aux ressources demandés, à savoir le nombre fois ou cette ressource est demandée, le nombre de visiteurs uniques, la bande passante représentée, la méthode et l'URL de la ressource.
            
            :return: dictionnaire des données
            :rtype: dict

            """
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
            """
            détermine les données liés aux noms de domaine demandés, à savoir le nombre fois ou ce nom de domaine est demandé, le nombre de visiteurs uniques, la bande passante représentée, la méthode et le nom de domaine en question.
            
            :return: dictionnaire des données
            :rtype: dict

            """
            referrer_list = [referrer.domain for referrer in self.token_dict["Referrer"]]
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
            """
            détermine les données liés aux visiteurs, à savoir le nombre fois que le visiteur s'est connecté au serveurs, le nombre des différentes URL demandées, la bande passante représentée, et l'adresse IP du visteurs.
            
            :return: dictionnaire des données
            :rtype: dict

            """
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
        self.stat_dict["TopUniqueResponses"] = topuniqueresponses()  # SubDict: ["2xx Success", "3xx Redirection", "4xx Client Error", "5xx Server Error"]

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
        """
        Permet de trier une liste nous permettant de récupérer des valeurs triées de nos données à l'affichage.

        :param liste: une liste
        :type liste: list
        :return: indices des valeurs que l'on souhaite afficher dans l'ordre de leurs futur affichage
        :rtype: list

        """
        indices = [0]
        valeurs = [liste[0]]
        for i in range(1, len(liste)):
            if len(valeurs) < self.line:
                indices.append(i)
                valeurs.append(liste[i])
            else:
                if liste[i] >= min(valeurs) and i not in indices:
                    ind = valeurs.index(min(valeurs))
                    indices[ind] = i
                    valeurs[ind] = liste[i]
        valeurs, indices = (list(t) for t in zip(*sorted(zip(valeurs, indices), reverse=True)))
        return indices
    
    def get_topfiles(self, stat):
        """
        Ordonne la liste des top files et s'assure de sa configuration afin d'obtenir un affichage lisible des résultats.

        :param stat: dictionnaire de statistiques
        :type stat: dict
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
        Ordonne la liste des top referrers et s'assure de sa configuration afin d'obtenir un affichage lisible des résultats.

        :param stat: dictionnaire de statistiques
        :type stat: dict
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
        Ordonne la liste des top visitors et s'assure de sa configuration afin d'obtenir un affichage lisible des résultats

        :param stat: dictionnaire de statistiques
        :type stat: dict
        :return: Liste des strings organisées.
        :rtype: list
        
        """
        indices = self.get_indices_top(stat["Hits"])
        L = []
        for i in indices:
            L.append("\033[36m" + self.format_byte(stat["Bandwidth"][i]) + "\033[0m\t\t\033[91m" + str(stat["Hits"][i]) + "\033[0m\t\033[92m" + str(stat["Visits"][i]) + "\033[0m\t\033[97m" + str(stat["IP"][i]) + "\033[0m")
        return L

    def get_topuniqueresponses(self, stat):
        """
        Ordonne la liste des top unique responses et s'assure de sa configuration afin d'obtenir un affichage lisible des résultats.

        :param stat: dictionnaire de statistiques
        :type stat: dict
        :return: Liste des strings organisées.
        :rtype: list

        """
        indices = self.get_indices_top(stat["Hits"])
        L = []
        for i in indices:
            L.append("\033[36m" + self.format_byte(stat["Bandwidth"][i]) + "\033[0m\t\t\033[91m" + str(
                stat["Hits"][i]) + "\033[0m\t\033[92m" + str(stat["Visitors"][i]) + "\033[0m\t\033[97m" + str(
                stat["Code"][i]) + "\033[0m")
        return L
        
    def get_attack(self, attack):
        """
        Ordonne la liste des potentiels attaques et s'assure de sa configuration afin d'obtenir un affichage lisible des résultats.

        :param attack: dictionnaire d'attaque.
        :type attack: dict
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
        #L.append("\n\033[100m\033[97m\033[1m   4 - DANGER - order by number of hits, then by impact (desc)\t\t\t\t\t\t\033[0m\n")
       # for url, e in L2[:self.line]:
            #L.append("\033[37mURL\033[0m\033[35m " + str(url) + "\033[0m\n\t\033[93mImpact\033[0m\t\t\033[93m" + str(e[2]) + "\033[0m\n\t\033[92mDescription\033[0m\t\033[92m" + str(e[1]) + "\033[0m\n\t\033[91mHits\033[0m\t\t\033[91m" + str(len(e[0])) + "\033[0m\n\t\033[37mLogLineNumbers\033[0m\t\033[37m" + ", ".join(e[0]) + "\033[0m\n\n")
        L3 = sorted(d.items(), key=lambda e: (-e[1][2], -len(e[1][0])))
        L.append("\n\033[100m\033[97m\033[1m   5 - DANGER - order by impact, then by number of hits (desc)\t\t\t\t\t\t\033[0m\n")
        for url, e in L3[:self.line]:
            L.append("\033[37mURL\033[0m\033[35m " + str(url) + "\033[0m\n\t\033[93mImpact\033[0m\t\t\033[93m" + str(e[2]) + "\033[0m\n\t\033[92mDescription\033[0m\t\033[92m" + str(e[1]) + "\033[0m\n\t\033[91mHits\033[0m\t\t\033[91m" + str(len(e[0])) + "\033[0m\n\t\033[37mLogLineNumbers\033[0m\t\033[37m" + ", ".join(e[0]) + "\033[0m\n\n")
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

    def get_report(self):
        """
        Ordonne les donnée issues des statistiques et des analyses, prépare pour l'affichage finale.

        :return: tableau des lignes de résultats à partir des dictionnaires
        :rtype: list

        """
        
        D = time.strftime('%d/%m/%y %H:%M',time.localtime())  
        report = list()
        report.append("\n\n\n\n\n\033[100m\033[97m\033[1m   Analyse générale du fonctionnement\t\t" + str(D) + "\t\t\t\t\t\t\033[0m\n")            stat_keys = self.stat_dict.keys()
        for key in stat_keys:
            stat = self.stat_dict[key]
            if key == "TotalVisitors":
                key = "TotalRequests"
            if key == "ValidRequests":
                key = "SuccessfulRequest"
            if key == "NotFoundURL":
                key = "Unique404"
            if type(stat) == int:
                report.append("\t\033[97m" + str(key) + "\033[0m\033[92m\t " + str(stat) + "\033[0m")
        for key in stat_keys:
            stat = self.stat_dict[key]
            if type(stat) != int:
                if str(key) == "TopFiles":
                    topfiles = self.get_topfiles(stat)
                    report.append("\n\033[100m\033[97m\033[1m   1 - TOP FILES (URLs)\t\t\t\t\t\t\t\t\t\t\t\033[0m\n")
                    report.append("\033[37mBandwidth\tHits\tVisitors\tMethod\tURL")
                    report.append("---------\t----\t--------\t------\t---\033[0m")
                    for ligne in topfiles:
                        report.append(ligne)
                    report.append("")
                elif str(key) == "TopReferrers":
                    topreferrers = self.get_topreferrers(stat)
                    report.append("\n\033[100m\033[97m\033[1m   2 - TOP REFERRERS (Sites)\t\t\t\t\t\t\t\t\t\t\033[0m\n")
                    report.append("\033[37mBandwidth\tHits\tVisitors\tMethod\tReferrer")
                    report.append("---------\t----\t--------\t------\t--------\033[0m")
                    for ligne in topreferrers:
                        report.append(ligne)
                    report.append("")
                elif str(key) == "TopVisitors":
                    topvisitors = self.get_topvisitors(stat)
                    report.append("\n\033[100m\033[97m\033[1m   3 - TOP VISITORS (Hostname or IP)\t\t\t\t\t\t\t\t\t\033[0m\n")
                    report.append("\033[37mBandwidth\tHits\tVisits\tIP")
                    report.append("---------\t----\t------\t--\033[0m")
                    for ligne in topvisitors:
                        report.append(ligne)
                    report.append("")
                elif str(key) == "TopUniqueResponses":
                    topuniqueresponses = self.get_topuniqueresponses(stat)
                    report.append("\n\033[100m\033[97m\033[1m   4 - HTTP Status Codes\t\t\t\t\t\t\t\t\t\t\033[0m\n")
                    report.append("\033[37mBandwidth\tHits\tVisits\tCode")
                    report.append("---------\t----\t------\t--\033[0m")
                    for ligne in topuniqueresponses:
                        report.append(ligne)
                    report.append("")
        attack = self.attack_dict
        attacks = self.get_attack(attack)
        for ligne in attacks:
            report.append(ligne)
        report.append("\033[100m\033[97m\033[1m   Fin de l'analyse\t\t\t\t\t\t\t\t\t\t\t\033[0m\n\n\n\n\n")
    return report
