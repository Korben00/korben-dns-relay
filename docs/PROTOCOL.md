# Protocole v1

`POST /v1/query` via TLS 1.3. Type `application/octet-stream`, sans
paramètres d’URL, redirection, compression HTTP ou cookie. En privé,
`Authorization: Bearer <64 chiffres hexadécimaux>`. Le jeton contrôle
l’accès ; TLS chiffre le lien. Aucun chiffrement propriétaire.

Enveloppe binaire :

| Champ | Taille | Valeurs |
|---|---:|---|
| Transport sortant | 1 | 0 UDP, 1 TCP |
| Famille IP | 1 | 4 IPv4, 6 IPv6 |
| IP de destination | 4 ou 16 | Binaire, ordre réseau, port 53 imposé |
| Requête | 17 à 1 232 | Message DNS, sans préfixe de longueur TCP |

Requête QUERY avec une question IN non compressée, RD=0. Pas de transfert
de zone, d’ANY, d’UPDATE ou d’options EDNS opaques. Un seul OPT EDNS(0) est
accepté : taille 512–1 232, DO facultatif, et éventuellement un seul
remplissage constitué d’octets zéro. Pas d’ECS, de cookies DNS ou de TSIG.

Réponse HTTP 200 : message DNS brut, sans enveloppe. L’ID original est
rétabli après l’échange sortant avec un ID aléatoire et vérification de
l’ID, du sens, de l’opcode et de la question. UDP est borné à la taille
annoncée, ou à 512 sans EDNS. TCP est borné à 65 535 octets ; les lectures
respectent la longueur DNS TCP. Le client décide de réessayer en TCP après
une réponse UDP tronquée. Pas de réessai automatique vers un autre service.

Réponses HTTP sans corps : 400 enveloppe invalide, 401 jeton absent ou
invalide, 403 destination refusée, 404 mauvais chemin, 405 méthode,
413 taille, 415 type ou encodage, 429 quota, 502 échec de transport ou
réponse incompatible, 504 délai. Toutes les réponses sont `no-store`.
L’analyse DNSSEC et la validation des enregistrements restent à la charge
du résolveur.

## Intégration prévue dans KORBEN DNS

Le choix de l’autorité et les échanges itératifs restent dans Unbound.
Le point de raccordement est `outnet_serviced_query` dans
`services/outside_network.c`, sous le choix de l’adresse autoritative,
avec une passerelle locale asynchrone. Celle-ci assure TLS et la
réutilisation des connexions HTTP/2. Un `forward-zone` vers le relais
déléguerait la récursion et ne convient pas ; un `stub-zone` racine ne
transporterait pas les étapes suivantes.

La première intégration peut réutiliser le chemin TCP événementiel
d’Unbound en mode relais. L’adresse autoritative d’origine doit rester la
clé interne de la requête. Sécuriser le canal local par un secret de
session ou le contrôle d’accès du système, et empêcher toute émission
directe UDP/TCP 53 quand le mode relais strict est choisi. Laisser les
zones privées, les filtres, le cache et DNSSEC locaux.

Dans l’application : choix explicite « Direct », « Relais officiel »,
« Relais personnalisé ». Le relais personnalisé reçoit une URL HTTPS,
une IP d’amorçage si nécessaire et, en privé, un jeton stocké dans le
trousseau système. Pour l’officiel, distribuer une liste d’IP de démarrage
vérifiées et prévoir leur rotation. Ne jamais incorporer un jeton partagé
à l’application. Expliquer ce que le relais voit et afficher le mode
effectif. Aucun changement automatique de fournisseur à l’insu de
l’utilisateur.

Le prototype ne modifie pas Unbound. Avant intégration, qualifier le
transport avec les trois niveaux d’une hiérarchie signée sur un réseau
de test où le port 53 est bloqué côté client. Le relais doit faire seul
les sorties 53. Tester sur chaque OS, cache froid et chaud, sans
émission de zones privées, avec signatures invalides, troncature,
réponses lentes, arrêt/reprise et certificats invalides.
