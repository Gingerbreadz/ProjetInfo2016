"""
test d'intégration : on vérifie la cohérence de l'ensemble (manque certains tests).
"""

import sys
path = "../"
sys.path.append(path)
from loganalyser import fichier as f
from loganalyser import outils as o
from loganalyser import diagnostique as d
from loganalyser import token as t




" test unitaire classe outils"   #Pour tester utiliser la commande 
print("-----test outils.py-----")
print("====test constructeur====\n")
keylist=["IP", "Name", "Date", "Ext", "Methode", "URL", "Response", "Byte", "Referrer"]
testDic = o.Dictionary(keylist)
print("Dictionnaire attendu: " )
dicAtt={"IP":[], "Name":[], "Date":[], "Ext":[], "Methode":[], "URL":[], "Response":[], "Byte":[], "Referrer":[]}
print(dicAtt)
print("Dictionnaire obtenu :")
print(testDic)
if testDic == dicAtt:
    print("Le constructeur fonctionne !\n")
else :
    print('mauvaise construction')
    quit()



    
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
    quit()
    
    
print("===test methode addentry====\n")
newEntry=['0.0.0.0','toto','09/May/2016:17:58:48', '-0700', 'GET', 'www.urlexemple.com', '200', '2326','http://www.example.com/start.html']
testDic.addentry(newEntry)
print('resultat attendu\n')
resatt={'Ext': ['-0700'], 'Byte': ['2326'], 'Response': ['200'], 'Methode': ['GET'], 'Date': ['09/May/2016:17:58:48'], 'URL': ['www.urlexemple.com'], 'IP': ['0.0.0.0'], 'Referrer': ['http://www.example.com/start.html'], 'Name': ['toto']}
print(resatt)
print('resultat obtenu\n')
print(testDic)
if resatt==testDic:
    print('La méthode addentry fonctionne\n')
else :
     print('La méthode addentry ne fonctionne pas\n')
     quit()
print("test levée d'exception addentry \n")
print("on teste : testDic.addentry(['0.0.0.0']) : une exception doit être levée\n")
try:
    testDic.addentry(['0.0.0.0'])
except Exception:
    print("une exception a bien été levée\n")
else:
    print("l'exception n'a pas été levée")
    quit()
     
     
     
     
     
     
print("===test methode __getitem__====\n")
print("résultat attendu:\n")
resAttendu=newEntry
print(resAttendu)
resObtenu=[]
print("\n résultat obtenu")

for k in keylist:
    resObtenu+=testDic.__getitem__(k)
print(resObtenu)

if resObtenu==resAttendu :
    print('__getitem__ fonctionne\n')
else :
    print('getitem ne fonctionne pas')
    quit()

print("test levée d'exception __getitem__\n") 
print("on teste : testDic.__getitem__('WrongKey') : une exception doit être levée\n")
try:
    testDic.__getitem__('WrongKey')
except Exception:
    print("l'exception a bien été levée\n")
else:
    print("l'exception n'a pas été levée")
    quit()

print("====test getentry====\n")
newEntry2=['1.1.1.1','toto1','09/May/2016:18:58:48', '-0700', 'DELETE', 'www.urlexemple2.com', '404', '4652','http://www.example2.com/start.html']
print("ajout d'une seconde entrée:['1.1.1.1','toto1','09/May/2016:18:58:48', '-0700', 'DELETE', 'www.urlexemple2.com', '404', '4652','http://www.example2.com/start.html']\n")
testDic.addentry(newEntry2)
print("resultat attendu :\n")
print("index 0:" ,newEntry,"\n", "index 1 : ",newEntry2,"\n" )
print("résultat obtenu\n")
res0=testDic.getentry(0)
res1=testDic.getentry(1)
print("index 0 : ",res0,"\n","index 1 : ", res1,"\n")
nbOk=0
for i in range (len(newEntry2)) :
    if res1[i] in newEntry2:
      nbOk+=1
    else :
        print("getentry ne fonctionne pas\n")
        quit()
if nbOk==len(newEntry2):
    print("getentry fonctionne \n")

print("test levée d'exception getentry \n")
print("on teste : testDic.getentry(len(self.__getitem__(self._keys[0]))) : une exception doit être levée\n")
try:
    testDic.getentry(len(testDic.__getitem__(testDic._keys[0])))
except Exception:
    print("une exception a bien été levée\n")
else:
    print("l'exception n'a pas été levée") 
    quit()



print("====test itemtoentrynumbers====\n")   #la fonction ne fonctionne pas, cf outils.py
testDic["IP"][0]=t.IP(testDic["IP"][0])
testDic["IP"][1]=t.IP(testDic["IP"][1])
testDic["Name"][0]=t.Name(testDic["Name"][0])
testDic["Name"][1]=t.Name(testDic["Name"][1])
testDic["Date"][0]=t.Date(testDic["Date"][0])
testDic["Date"][1]=t.Date(testDic["Date"][1])
testDic["Ext"][0]=t.EXT(testDic["Ext"][0])
testDic["Ext"][1]=t.EXT(testDic["Ext"][1])
testDic["Methode"][0]=t.Method(testDic["Methode"][0])
testDic["Methode"][1]=t.Method(testDic["Methode"][1])
testDic["URL"][0]=t.URL(testDic["URL"][0])
testDic["URL"][1]=t.URL(testDic["URL"][1])
testDic["Response"][0]=t.Response(testDic["Response"][0])
testDic["Response"][1]=t.Response(testDic["Response"][1])
testDic["Byte"][0]=t.Byte(testDic["Byte"][0])
testDic["Byte"][1]=t.Byte(testDic["Byte"][1])
testDic["Referrer"][0]=t.Referer(testDic["Referrer"][0])
testDic["Referrer"][1]=t.Referer(testDic["Referrer"][1])
resObt=testDic.itemtoentrynumbers(t.IP('1.1.1.1').donnee)
resAtt=[1]

if resObt==resAtt :
    print("itemtoentrynumbers fonctionne\n")
else:
    print("itemtoentrynumbers ne fonctionne pas\n")

print("test levée d'exception itemtoentrynumbers \n")
print("on teste : testDic.itemetoentrynumbers('2.2.2.2') : une exception doit être levée\n")
try:
    testDic.itemetoentrynumbers(t.IP('2.2.2.2').donnee)
except Exception:
    print("une exception a bien été levée\n")
else:
    print("l'exception n'a pas été levée")
    quit()
