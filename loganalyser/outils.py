"""
Sert à l'implémentation de notre classe Dictionnaire, qui étend la classe dict de Python, et y ajoute les opérations
qui nous sont utiles sur les dictionnaires.
"""


class Dictionary(dict):
    """
    Extension de la classe dictionnaire. Cette classe possède comme attributs supplémentaires:
    - La liste des clefs du dictionnaire
    """

    def __init__(self, keylist):
        """
        Constructeur de classe. Un dictionnaire est initialisé vide à partir de la liste des clefs
        :param keylist: Liste des clefs du dictionnaire.
        :type keylist: list
        """
        super(Dictionary, self).__init__()
        self._keys = keylist
        for key in self._keys:
            self.__setitem__(key, [])
        return

    def __getitem__(self, key):
        """
        Retourne les valeurs de la clefs passée en argument.
        :param key: Clef
        :type key: str
        :return: Liste contenant les valeurs de la clef passée en argument.
        :rtype: list
        :raises: unvalid key exception
        
        """
        if key not in self._keys:
            raise Exception("'" + key + "'" + " n'est pas une clef valide")
        return dict.__getitem__(self, key)

    def keys(self):
        """
        Retourne les clefs du dictionnaire.
        :return: Liste contenant les clefs du dictionnaire.
        :rtype: list
        """
        return self._keys

    def addentry(self, entry):
        """
        Ajoute au dicitonnaire une nouvelle valeur dans chacunes de ses clefs à partir d'une liste.
        :param entry: Liste contenant les valeurs pour chacune des clefs
        :type entry: list
        """
        if not len(entry) == len(self._keys):
            raise Exception("La liste n'est pas de bonne longueur")
        i = 0
        for key in self._keys:
            self.__setitem__(key, self.__getitem__(key)+[entry[i]])
            i += 1

    def getentry(self, entrynumber):
        """
        Retourne la liste contenant les valeurs de chaques clefs pour un index donné.
        :param entrynumber: index de l'entrée.
        :type entrynumber: int
        :return: Liste contenant les valeurs de chaques clefs pour le même index.
        :rtype: list
        """
        if not entrynumber < len(self.__getitem__(self._keys[0])) and entrynumber >= 0:
            raise Exception("'" + str(entrynumber) + "'" + " ne correspond pas à index d'entrée valide")
        return [self[key][entrynumber] for key in self.keys()]

    def itemtoentrynumbers(self, item):
        """
        Retourne l'index d'une valeur dans le dictionnaire.
        :param item: valeur recherchée.
        :type item: str
        :return: Liste contenant les index associés à la valeur d'entrée.
        :rtype: list
        """
        entrynumbers = []
        for key in self.keys():
            if item in [x.donnee for x in self[key]]:
                for i in range(0, len(self[key])):
                    if self[key][i].donnee == item:
                        entrynumbers.append(i)
        if len(entrynumbers) == 0:
            raise Exception("'" + str(item) + "'" + " n'est pas dans le dictionnaire")
        return entrynumbers
