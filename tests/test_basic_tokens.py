# -*- coding: utf-8 -*-
"""
test unitaire sur le module token
"""


from loganalyser import token as t
from datetime import datetime

print("-----test token.py-----")
print("====test Classe IP====\n\ħ")
print("=====test du constructeur===")
ipTest=t.IP('1.1.1.1')
print("résultat attendu : \n ipTest.donnee = '1.1.1.1' \n ")
print("résultat obtenu : \n ipTest.donnee = ", ipTest.donnee,"\n")
if ipTest.donnee=="1.1.1.1":
    print("le constructeur fonctionne !\n")
else :
    print("le constructeur ne fonctionne pas ...")
    quit()

print("on teste : ipTest=token.IP('1.2.1') : une exception doit être levée\n")
try:
    ipTest=t.IP('1.2.1') 
except ValueError:
    print("ValueError : une exception a bien été levée\n")
else:
    print("l'exception n'a pas été levée")
    quit()



print("====test Classe Name====\n")
print("=====test du constructeur===")
nameTest=t.Name('Toto')
print("résultat attendu : \n nameTest.donnee = 'Toto' \n ")
print("résultat obtenu : \n nameTest.donnee = ", nameTest.donnee,"\n")
if nameTest.donnee=="Toto":
    print("le constructeur fonctionne !\n")
else :
    print("le constructeur ne fonctionne pas ...")
    quit()

print("on teste : nameTest=token.Name(45) : une exception doit être levée\n")
try:
    nameTest=t.Name(45)
except ValueError:
    print("ValueError : une exception a bien été levée\n")
else:
    print("l'exception n'a pas été levée")
    quit()
    

print("====test Classe Date====\n")   
print("=====test du constructeur===")
dateTest=t.Date('06/Sep/2014:15:25:45')
print("résultat attendu : \n dateTest.donnee = '06/Sep/2014:15:25:45' \n ")
print("résultat obtenu : \n dateTest.donnee = ", dateTest.donnee,"\n")
if datetime.strptime(dateTest.donnee, '%d/%b/%Y:%H:%M:%S')==datetime.strptime('06/Sep/2014:15:25:45', '%d/%b/%Y:%H:%M:%S'):
    print("le constructeur fonctionne !\n")
else :
    print("le constructeur ne fonctionne pas ...")
    quit()

print("on teste : dateTest=token.Name(45) : une exception doit être levée\n")
try:
    dateTest=t.Date(45)   #test à revoir
except ValueError:
    print("ValueError : une exception a bien été levée\n")
else:
    print("l'exception n'a pas été levée")
    quit()
    
    
    
print("====test Classe Method====\n")
print("=====test du constructeur===")
methTest=t.Method('GET')
print("résultat attendu : \n methTest = t.Method('GET') \n ")
print("résultat obtenu : \n methTest.donnee = ", methTest.donnee,"\n")
if methTest.donnee=="GET":
    print("le constructeur fonctionne !\n")
else :
    print("le constructeur ne fonctionne pas ...")
    quit()

print("on teste : methTest=token.Methode('notaMethode'): une exception doit être levée\n")
try:
    methTest=t.Method('NotAMethod')
except ValueError:
    print("ValueError : une exception a bien été levée\n")
else:
    print("l'exception n'a pas été levée")
    quit()






print("====test Classe Byte====\n")
print("=====test du constructeur===")
byteTest=t.Byte('1048')
print("résultat attendu : \n byteTest.donnee = '1048' \n ")
print("résultat obtenu : \n byteTest.donnee = ", byteTest.donnee,"\n")
if byteTest.donnee=="1048":
    print("le constructeur fonctionne !\n")
else :
    print("le constructeur ne fonctionne pas ...")
    quit()

print("on teste : bbyteTest=t.Byte('NotAnInt') : une exception doit être levée\n")

try:
    byteTest=t.Byte('NotAnInt')
except ValueError:
    print("ValueError : une exception a bien été levée\n")
else:
    print("l'exception n'a pas été levée")
    quit()
