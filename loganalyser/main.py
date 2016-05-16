"""
Boucle principale
Pour l'instant vide
C'est ici que seront implémentées les intéractions avec l'utilisateur et utilisées les classes/méthodes des autres modules.
TODO: écrire démarche globale du programme. Ajouter Interfaces avec les inputs (arguments) et les outputs (std_out) | Pas de Reste.
"""

import sys
from loganalyser import fichier
from loganalyser import outils


def recuperertokens(cheminfichier):
    log_dic = outils.dictionary()
    fichierdelog = fichier.FichierDeLog(cheminfichier)
    for i in range(0, fichierdelog.nbLigne):
        ligne = fichierdelog.decouperligne(i)
        log_dic.addEntry(ligne)
    return log_dic


def recupererregexp(cheminfichier):
    regexp_dic = outils.dictionary()
    fichierregexp = fichier.FichierRegExp(cheminfichier)
    for i in range(0, fichierregexp.nbLigne):
        ligne = fichierregexp.decouperligne(i)
        regexp_dic.addEntry(ligne)
    return regexp_dic


def main():
    logfilepath = sys.argv[0]
    regexpfilepath = sys.argv[1]
    log_dic = recuperertokens(logfilepath)
    regexp_dic = recupererregexp(regexpfilepath)
    pass

if __name__ == '__main__':
    sys.exit(main())
