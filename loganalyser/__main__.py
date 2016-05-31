""""
Boucle principale
C'est ici que sont implémentées les intéractions avec l'utilisateur et utilisées les classes/méthodes des autres
modules.
"""

import sys
import os
import time
import re
from loganalyser import fichier
from loganalyser import outils
from loganalyser import diagnostique
from loganalyser import token

tokenkeys = ["IP", "Name", "Date", "Ext", "Method", "URL", "Response", "Byte", "Referrer"]
regexkeys = ["Number", "Rule", "Description", "Impact"]


def listtotokenlist(liste):
    """
    Retourne une ligne de logs sous la forme d'une liste tokenisée avec des champs corrects

    :param liste: ligne de log mise sous forme de liste 
    :type liste: list
    :return: liste des tokens correctement instanciés et vérifiés
    :rtype: list
    
    """
    s = list()
    s.append(token.IP(liste[0]))
    s.append(token.Name(liste[1]))
    s.append(token.Date(liste[2]))
    s.append(token.EXT(liste[3]))
    s.append(token.Method(liste[4]))
    s.append(token.URL(liste[5]))
    s.append(token.Response(liste[6]))
    s.append(token.Byte(liste[7]))
    s.append(token.Referer(liste[8]))
    return s


def recuperertokens(cheminfichier):
    """
    Retourne un dictionnaire des logs tokenisés à partir d'un ficher du type 'access.log'

    :param cheminfichier: emplacment où récupérer la ressource
    :type cheminfichier: str
    :return: dictionnaire des logs
    :rtype: dict
    
    """
    matchfail = 0
    log_dic = outils.Dictionary(tokenkeys)
    fichierdelog = fichier.FichierDeLog(cheminfichier)
    for i in range(0, fichierdelog.nbLigne):
        ligne_log = fichierdelog.decouperligne(i)
        if ligne_log[0] == "NoMatch":
            matchfail += 1
        else:
            tokenlist = listtotokenlist(ligne_log)
            log_dic.addentry(tokenlist)
    fichierdelog.fermerfichier()
    return [log_dic, matchfail]


def recupererregexp(cheminfichier):
    """
    Retourne un dictionnaire de regexp utilisable afin d'analyser les logs

    :param cheminfichier: emplacment où récupérer la ressource
    :type cheminfichier: str
    :return: dictionnaire des regexp
    :rtype: dict
    
    """
    regexp_dic = outils.Dictionary(regexkeys)
    fichierregexp = fichier.FichierRegExp(cheminfichier)
    for i in range(0, len(fichierregexp.doc)):
        ligne_reg = fichierregexp.decouperligne(i)
        regexp_dic.addentry(ligne_reg)
    fichierregexp.fermerfichier()
    return regexp_dic


def main():
    n = 5
    if len(sys.argv) > 2:
        n = int(sys.argv[2])

    logfilepath = sys.argv[1]
    #regexpfilepath = str(list(re.compile("(.*)([/].*)([/].*)").match(__file__).groups('default'))[0]) + "/default_filter.xml"
    regexpfilepath = "./res/default_filter.xml"
    #print("\n\nOuverture et découpage du fichier de log:",)
    #start_time1 = time.time()
    log_dic, nomatchcount = recuperertokens(logfilepath)
    #end_time1 = time.time()
    #print("\t%s seconds\n" % (end_time1 - start_time1))
    #input("\tPress Enter to continue...\n")

    #print("Ouverture et découpage du fichier de regles:",)
    #start_time2 = time.time()
    regexp_dic = recupererregexp(regexpfilepath)
    #end_time2 = time.time()
    #print("\t%s seconds\n" % (end_time2 - start_time2))
    #input("\tPress Enter to continue...\n")

    #print("Création du Diagnostique:",)
    #start_time3 = time.time()
    diag = diagnostique.Diagnostique(log_dic, regexp_dic, n, nomatchcount)
    #end_time3 = time.time()
    #print("\t%s seconds\n" % (end_time3 - start_time3))
    #input("\tPress Enter to continue...\n")

    #print("Ecriture du Rapport:",)
    #start_time4 = time.time()
    report = diag.get_report()
    #end_time4 = time.time()
    #print("\t%s seconds\n" % (end_time4 - start_time4))
    #input("\tPress Enter to continue...\n")

    os.system('cls' if os.name == 'nt' else 'clear')

    if len(sys.argv) > 3:
        fichiersortie = fichier.FichierRapportTextuel(sys.argv[3])
        fichiersortie.ecriretexte(report)
    else:
        for ligne in report:
            print(ligne)

    return

if __name__ == '__main__':
    sys.exit(main())
