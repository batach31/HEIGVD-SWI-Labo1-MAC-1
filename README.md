[Livrables](#livrables)

[Échéance](#échéance)

[Quelques pistes importantes](#quelques-pistes-utiles-avant-de-commencer-)

[Travail à réaliser](#travail-à-réaliser)

1. [Deauthentication attack](#1-deauthentication-attack)
2. [Fake channel evil tween attack](#2-fake-channel-evil-tween-attack)
3. [SSID Flood attack](#3-ssid-flood-attack)

# Sécurité des réseaux sans fil

## Laboratoire 802.11 MAC 1

__A faire en équipes de deux personnes__

### Pour cette partie pratique, vous devez être capable de :

*	Détecter si un certain client WiFi se trouve à proximité
*	Obtenir une liste des SSIDs annoncés par les clients WiFi présents

Vous allez devoir faire des recherches sur internet pour apprendre à utiliser Scapy et la suite aircrack pour vos manipulations. __Il est fortement conseillé d'employer une distribution Kali__ (on ne pourra pas assurer le support avec d'autres distributions). __Si vous utilisez une VM, il vous faudra une interface WiFi usb, disponible sur demande__.

__ATTENTION :__ Pour vos manipulations, il pourrait être important de bien fixer le canal lors de vos captures et/ou vos injections (à vous de déterminer si ceci est nécessaire pour les manipulations suivantes ou pas). Si vous en avez besoin, la méthode la plus sure est d'utiliser l'option :

```--channel``` de ```airodump-ng```

et de garder la fenêtre d'airodump ouverte en permanence pendant que vos scripts tournent ou vos manipulations sont effectuées.


## Quelques pistes utiles avant de commencer :

- Si vous devez capturer et injecter du trafic, il faudra configurer votre interface 802.11 en mode monitor.
- Python a un mode interactif très utile pour le développement. Il suffit de l'invoquer avec la commande ```python```. Ensuite, vous pouvez importer Scapy ou tout autre module nécessaire. En fait, vous pouvez même exécuter tout le script fourni en mode interactif !
- Scapy fonctionne aussi en mode interactif en invoquant la commande ```scapy```.  
- Dans le mode interactif, « nom de variable + <enter> » vous retourne le contenu de la variable.
- Pour visualiser en détail une trame avec Scapy en mode interactif, on utilise la fonction ```show()```. Par exemple, si vous chargez votre trame dans une variable nommée ```beacon```, vous pouvez visualiser tous ces champs et ses valeurs avec la commande ```beacon.show()```. Utilisez cette commande pour connaître les champs disponibles et les formats de chaque champ.

## Travail à réaliser

### 1. Deauthentication attack

Une STA ou un AP peuvent envoyer une trame de déauthentification pour mettre fin à une connexion.

Les trames de déauthentification sont des trames de management, donc de type 0, avec un sous-type 12 (0x0c). Voici le format de la trame de déauthentification :

![Trame de déauthentification](images/deauth.png)

Le corps de la trame (Frame body) contient, entre autres, un champ de deux octets appelé "Reason Code". Le but de ce champ est d'informer la raison de la déauthentification. Voici toutes les valeurs possibles pour le Reason Code :

| Code | Explication 802.11                                                                                                                                     |
|------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0    | Reserved                                                                                                                                              |
| 1    | Unspecified reason                                                                                                                                    |
| 2    | Previous authentication no longer valid                                                                                                               |
| 3    | station is leaving (or has left) IBSS or ESS                                                                                                          |
| 4    | Disassociated due to inactivity                                                                                                                       |
| 5    | Disassociated because AP is unable to handle all currently associated stations                                                                        |
| 6    | Class 2 frame received from nonauthenticated station                                                                                                  |
| 7    | Class 3 frame received from nonassociated station                                                                                                     |
| 8    | Disassociated because sending station is leaving (or has left) BSS                                                                                    |
| 9    | Station requesting (re)association is not authenticated with responding station                                                                       |
| 10   | Disassociated because the information in the Power Capability element is unacceptable                                                                 |
| 11   | Disassociated because the information in the Supported Channels element is unacceptable                                                               |
| 12   | Reserved                                                                                                                                              |
| 13   | Invalid information element, i.e., an information element defined in this standard for which the content does not meet the specifications in Clause 7 |
| 14   | Message integrity code (MIC) failure                                                                                                                                              |
| 15   | 4-Way Handshake timeout                                                                                                                                              |
| 16   | Group Key Handshake timeout                                                                                                                                              |
| 17   | Information element in 4-Way Handshake different from (Re)Association Request/Probe Response/Beacon frame                                                                                                                                              |
| 18   | Invalid group cipher                                                                                                                                              |
| 19   | Invalid pairwise cipher                                                                                                                                              |
| 20   | Invalid AKMP                                                                                                                                              |
| 21   | Unsupported RSN information element version                                                                                                                                              |
| 22   | Invalid RSN information element capabilities                                                                                                                                              |
| 23   | IEEE 802.1X authentication failed                                                                                                                                              |
| 24   | Cipher suite rejected because of the security policy                                                                                                                                              |
| 25-31 | Reserved                                                                                                                                              |
| 32 | Disassociated for unspecified, QoS-related reason                                                                                                                                              |
| 33 | Disassociated because QAP lacks sufficient bandwidth for this QSTA                                                                                                                                              |
| 34 | Disassociated because excessive number of frames need to be acknowledged, but are not acknowledged due to AP transmissions and/or poor channel conditions                                                                                                                                              |
| 35 | Disassociated because QSTA is transmitting outside the limits of its TXOPs                                                                                                                                              |
| 36 | Requested from peer QSTA as the QSTA is leaving the QBSS (or resetting)                                                                                                                                              |
| 37 | Requested from peer QSTA as it does not want to use the mechanism                                                                                                                                              |
| 38 | Requested from peer QSTA as the QSTA received frames using the mechanism for which a setup is required                                                                                                                                              |
| 39 | Requested from peer QSTA due to timeout                                                                                                                                              |
| 40 | Peer QSTA does not support the requested cipher suite                                                                                                                                              |
| 46-65535 | Reserved                                                                                                                                              |
 
a) Utiliser la fonction de déauthentification de la suite aircrack, capturer les échanges et identifier le Reason code et son interpretation.

__Question__ : quel code est utilisé par aircrack pour déauthentifier un client 802.11. Quelle est son interpretation ?

Nous avons pu voir que airecrack utilisait le code 7 pour déauthentifier les clients.
![Code de désauthentification](images/aircrack_deauth_code.jpg)

__Question__ : A l'aide d'un filtre d'affichage, essayer de trouver d'autres trames de déauthentification dans votre capture. Avez-vous en trouvé d'autres ? Si oui, quel code contient-elle et quelle est son interpretation ?

Oui, nous avons vu d'autres trames de déauthentification, ces dernières utilisaient toutes le code 7 pour désauthentifier leurs clients.
![Trames de désauthentification](images/aircrack_multiple_deauth.JPG)

b) Développer un script en Python/Scapy capable de générer et envoyer des trames de déauthentification. Le script donne le choix entre des Reason codes différents (liste ci-après) et doit pouvoir déduire si le message doit être envoyé à la STA ou à l'AP :
* 1 - Unspecified
* 4 - Disassociated due to inactivity
* 5 - Disassociated because AP is unable to handle all currently associated stations
* 8 - Deauthenticated because sending STA is leaving BSS

__Utilisation du script__

Avant de lancer le script de deauthentification *deauth.py* (sans arguments), il faut modifier le nom de l'interface *iface* utilisé ainsi que les variables *sta_mac* et *ap_mac* qui sont les adresses MAC de la station et de l'AP qu'on veut attaquer. Nous avons trouvé plus pratique de mettre ces variables à modifier dans le script plutôt qu'en argument en le lançant.\
Exemple d'utilisation:\
Le script va demander quelle raison utiliser pour la désauthentification. Suivant la réponse, le script enverra les trames de désauthentification à la STA cible ou à l'AP cible.\
![Deauthentication script](images/deauth_script.JPG)\

__Question__ : quels codes/raisons justifient l'envoie de la trame à la STA cible et pourquoi ?

Les codes 1, 4, 5 sont utilisés pour l'envoi de trames vers les STA cibles.
1 Parce que la raison n'est pas spécifiée et peut se retrouver dans n'importe quel cas.
4 Parce que l'AP détecte l'inactivité de la station cliente et le déconnecte pour libérer de l'espace.
5 Parce que l'AP est surchargé, il va donc déconnecter les STA qui se sont authentifiée en dernier.

__Question__ : quels codes/raisons justifient l'envoie de la trame à l'AP et pourquoi ?

Les codes 1 et 8 sont utilisés pour l'envoi de trames vers les AP cibles.
1 Pour les mêmes raison que précédemment
8 Parce que c'est la STA qui dit à l'AP qu'il quitte ce réseau.

__Question__ : Comment essayer de déauthentifier toutes les STA ?

En envoyant un broadcast, la valeur de la STA pour broadcast est ff:ff:ff:ff:ff:ff

__Question__ : Quelle est la différence entre le code 3 et le code 8 de la liste ?

Le code 3 est une deauthentication alors que le code 8 est une deassociation. Une deassociation peut se faire pour passer d'un AP à l'autre sans être deauthentifié, donc en restant connecté au même service. Alors qu'une deauthentication retire l'acces au service. (Il faut être authentifié avant de pouvoir s'associer à un AP).

__Question__ : Expliquer l'effet de cette attaque sur la cible

Les cibles de l'attaque se font déconnectées de leur AP. Si on émet les messages de deauth en continu, les cibles n'arrivent plus à se connecter.

### 2. Fake channel evil tween attack
a)	Développer un script en Python/Scapy avec les fonctionnalités suivantes :

* Dresser une liste des SSID disponibles à proximité
* Présenter à l'utilisateur la liste, avec les numéros de canaux et les puissances
* Permettre à l'utilisateur de choisir le réseau à attaquer
* Générer un beacon concurrent annonçant un réseau sur un canal différent se trouvant à 6 canaux de séparation du réseau original

__Question__ : Expliquer l'effet de cette attaque sur la cible

C'est une attaque par "spoofing" où on se fait passer pour un AP existant en l'imitant depuis un autre channel. Les victimes pensent qu'il s'agit d'un AP légitime et se connectent deçu, ce qui nous permet d'écouter leurs communications et/ou voler leurs informations.

Exemple d'utilisation:
D'abord démarrer le réseau wlan0 avec aircrack: ```sudo airmon-ng start wlan0```\
Puis lancer le script fakechannel.py\
![Fake Channel first step](images/fake_chanel_step_a.JPG)\
On nous demandera alors quel réseau on veut attaquer suivant les id des paquets obtenus\
![Fake Channel second step](images/fake_chanel_step_b.JPG)\
Ici on voit que le script envoie des trames se définissant comme l'AP que l'on souhaite mimer sur un channel se trouvant à une distance de 6.


### 3. SSID flood attack

Développer un script en Python/Scapy capable d'inonder la salle avec des SSID dont le nom correspond à une liste contenue dans un fichier text fournit par un utilisateur. Si l'utilisateur ne possède pas une liste, il peut spécifier le nombre d'AP à générer. Dans ce cas, les SSID seront générés de manière aléatoire.

Exemple d'utilisation avec 2 ssid randoms:
![ssidflood random](images/ssidflood_random.png)

![ssidflood random networks](images/ssidflood_random_networks.jpg)

Exemple d'utilisation avec un fichier text de ssids:
![ssidflood file](images/ssidflood_file.png)

![ssidflood file networks](images/ssidflood_file_networks.jpg)

## Livrables

Un fork du repo original . Puis, un Pull Request contenant :

- Script de Deauthentication de clients 802.11 __abondamment commenté/documenté__

- Script fake chanel __abondamment commenté/documenté__

- Script SSID flood __abondamment commenté/documenté__

- Captures d'écran du fonctionnement de chaque script

-	Réponses aux éventuelles questions posées dans la donnée. Vous répondez aux questions dans votre ```README.md``` ou dans un pdf séparé

-	Envoyer le hash du commit et votre username GitHub par email au professeur et à l'assistant


## Échéance

Le 9 mars 2020 à 23h59
