""""
Test de validation : Il s'agit de tester la boucle principale.
"""

from loganalyser import fichier
from loganalyser import outils
from loganalyser import diagnostique
from loganalyser import token

tokenkeys = ["IP", "Name", "Date", "Ext", "Method", "URL", "Response", "Byte", "Referrer"]
regexkeys = ["Number", "Rule", "Description", "Impact"]

logfilepath = "/home/anatole/Ecole/TSP/ProjetInfo/ProjetInfo2016/res/wwwminet-access.log"
regexpfilepath = "/home/anatole/Ecole/TSP/ProjetInfo/ProjetInfo2016/res/default_filter.xml"


def listtotokenlist(liste):
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
    log_dic = outils.Dictionary(tokenkeys)
    fichierdelog = fichier.FichierDeLog(cheminfichier)
    for i in range(0, fichierdelog.nbLigne):
        ligne_log = fichierdelog.decouperligne(i)
        if ligne_log:
            tokenlist = listtotokenlist(ligne_log)
            log_dic.addentry(tokenlist)
    fichierdelog.fermerfichier()
    return log_dic


def recupererregexp(cheminfichier):
    regexp_dic = outils.Dictionary(regexkeys)
    fichierregexp = fichier.FichierRegExp(cheminfichier)
    for i in range(0, len(fichierregexp.doc)):
        ligne_reg = fichierregexp.decouperligne(i)
        regexp_dic.addentry(ligne_reg)
    fichierregexp.fermerfichier()
    return regexp_dic

log_dict = recuperertokens(logfilepath)
regexp_dict = recupererregexp(regexpfilepath)
diag = diagnostique.Diagnostique(log_dict, regexp_dict)
report = diag.get_report(False)
for ligne in report:
    print(ligne)
