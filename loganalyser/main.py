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
    log = outils.dictionary()
    fichierdelog = fichier.FichierDeLog(cheminfichier)
    for i in range(0, fichierdelog.nbLigne):
        ligne = fichierdelog.decouperligne(i)
        log.addEntry(ligne)
    return log

def recupererregexp(cheminfichier):
    regex = 
    fichierregexp = fichier.FichierRegExp(cheminfichier)
    for i in range(0, fichierregexp.nbLigne):
        ligne = fichierregexp.decouperligne()

def main():
    logfilepath = sys.argv[0]
    regexfilepath = sys.argv[1]
    log = recuperertokens(logfilepath)




    pass

if __name__ == '__main__':
    sys.exit(main())

