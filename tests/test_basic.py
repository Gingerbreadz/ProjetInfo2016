"""
Aucun test n'a pour l'instant été écrit.
"""

import sys
path = "/home/antoine/ProjetInfo/ProjetInfo2016"
sys.path.append(path)
from loganalyser import fichier as f
from loganalyser import outils as o
from loganalyser import diagnostique as d
from loganalyser import token as t




" test unitaire classe outils"   #Pour tester utiliser la commande 
print("-----test outils.py-----")
print("---test constructeur----\n")
keylist=["IP", "Name", "Date", "Ext", "Methode", "URL", "Response", "Byte", "Referrer"]
testDic = o.Dictionary(keylist)
print("Dictionnaire attendu: " )
dicAtt={"IP":[], "Name":[], "Date":[], "Ext":[], "Methode":[], "URL":[], "Response":[], "Byte":[], "Referrer":[]}
print(dicAtt)
print("Dictionnaire obtenu :")
if testDic == dicAtt:
    print("Le constructeur fonctionne !\n")
else :
    print('mauvaise construction')





print("===test methode __getitem__====\n")
print("résultat attendu:\n")
resAttendu=9*[[]]
print(resAttendu)
resObtenu=[]
print("\n résultat obtenu")
for k in keylist:
    resObtenu.append(testDic.__getitem__(k))
    print(testDic.__getitem__(k))

if resObtenu==resAttendu :
    print('__getitem__ fonctionne\n')
else :
    print('getitem ne fonctionne pas')




    
print('===test methode keys====\n')
print('résultat attendu:\n')
print(keylist)
res=testDic.keys()
print('\n résultat obtenu\n')
print(res)
if res==keylist:
    print('la méthode keys fonctionne\n')
else :
    print('la méthode keys ne fonctionne pas\n')
    
    
print("===test methode addentry====\n")
newEntry=['0.0.0.0','toto','09/05/2016:17:58:48', '-0700', 'GET', 'www.urlexemple.com', '200', '2326','http://www.example.com/start.html']
testDic.addentry(newEntry)
print('resultat attendu\n')
resatt={'Ext': ['-0700'], 'Byte': ['2326'], 'Response': ['200'], 'Methode': ['GET'], 'Date': ['09/05/2016:17:58:48'], 'URL': ['www.urlexemple.com'], 'IP': ['0.0.0.0'], 'Referrer': ['http://www.example.com/start.html'], 'Name': ['toto']}
print(resatt)
print('resultat obtenu\n')
print(testDic)
if resatt==testDic:
    print('La méthode addentry fonctionne\n')
else :
     print('La méthode addentry ne fonctionne pas\n')