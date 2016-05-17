"""
Boucle principale
Pour l'instant vide
C'est ici que seront implémentées les intéractions avec l'utilisateur et utilisées les classes/méthodes des autres modules.
TODO: écrire démarche globale du programme. Ajouter Interfaces avec les inputs (arguments) et les outputs (std_out) | Pas de Reste.
"""

import sys
from loganalyser import fichier
from loganalyser import outils
from loganalyser import diagnostique
from loganalyser import token

out = sys.stdout
tokenkeys = ["IP", "Name", "Date", "Ext", "Methode", "URL", "Response", "Byte", "Referrer"]


def listtotokenlist(list):
    s = list.__init__()
    s.append(token.IP(list[0]))
    s.append(token.Name(list[1]))
    s.append(token.Date(list[2]))
    s.append(token.EXT(list[3]))
    s.append(token.Methode(list[4]))
    s.append(token.URL(list[5]))
    s.append(token.Response(list[6]))
    s.append(token.Byte(list[7]))
    s.append(token.Referer(list[8]))
    return s

def recuperertokens(cheminfichier):
    log_dic = outils.Dictionary(tokenkeys)
    fichierdelog = fichier.FichierDeLog(cheminfichier)
    for i in range(0, fichierdelog.nbLigne):
        ligne = fichierdelog.decouperligne(i)
        tokenlist = listtotokenlist(ligne)
        log_dic.addentry(tokenlist)
    return log_dic


def recupererregexp(cheminfichier):
    regexp_dic = []
    fichierregexp = fichier.FichierRegExp(cheminfichier)
    for i in range(0, fichierregexp.nbLigne):
        ligne = fichierregexp.decouperligne(i)
        regexp_dic.addentry(ligne)
    return regexp_dic


def main():
    logfilepath = sys.argv[0]
    regexpfilepath = sys.argv[1]
    log_dic = recuperertokens(logfilepath)
    regexp_dic = recupererregexp(regexpfilepath)
    diag = diagnostique.Diagnostique(log_dic, regexp_dic)
    report = diag.get_report(False)
    for ligne in report:
        out.write(ligne)
    pass

if __name__ == '__main__':
    sys.exit(main())
