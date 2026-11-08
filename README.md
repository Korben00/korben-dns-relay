# KORBEN DNS Relay

Prototype d’un **transport DNS itératif par HTTPS**. Un client lui donne
une adresse IP et un paquet DNS ; le relais contacte cette adresse sur le
port 53 et renvoie la réponse. Le relais ne suit pas les délégations, ne
valide pas DNSSEC, ne met rien en cache et n’interroge aucun résolveur amont.

L’objectif est que KORBEN DNS puisse continuer à faire sa récursion locale
sur un réseau qui bloque ou détourne les connexions DNS sortantes. Unbound
doit pouvoir joindre, via le même transport, les racines **et** les
serveurs de TLD et de domaine. Le relais ne parle pas le DoH standard
[RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html).

**État :** le serveur et le client Go de test sont utilisables de façon
autonome. Le transport n’est pas encore branché à l’application KORBEN DNS.
Aucune instance officielle n’est annoncée. Ce code a des tests de sécurité,
mais n’a pas reçu d’audit externe.

## Construire et essayer

Go 1.27.3 ou plus récent, avec les derniers correctifs de sécurité.
Le code utilise uniquement la bibliothèque standard. Il produit un
exécutable pour macOS, Linux et Windows.

```sh
go test ./...
go build -trimpath -o korben-dns-relay ./cmd/korben-dns-relay
```

Sous Windows, utilisez `-o korben-dns-relay.exe`. Préparez un certificat
TLS et sa clé. Le certificat doit couvrir le nom HTTPS du relais ; fournissez
la chaîne complète. Générez un jeton aléatoire, dans un répertoire privé :

```sh
(umask 077; ./korben-dns-relay token > token.hex)
./korben-dns-relay serve --listen 127.0.0.1:8443 \
  --cert fullchain.pem --key privkey.pem --token-file token.hex \
  --allow 198.41.0.4
```

Sous Windows, dans un répertoire dont les ACL sont limitées à votre
compte, créez le fichier avec
`.\korben-dns-relay.exe token | Set-Content -Encoding ascii token.hex`
puis lancez la commande `serve` sur une ligne. Restreignez les ACL du
jeton et de la clé au compte du service. Sous Unix, le fichier de jeton
doit être réservé à son propriétaire. Conservez les deux fichiers hors
du dépôt. Remplacez le jeton et redémarrez le relais pour révoquer l’ancien.

Avec un certificat de confiance pour `relay.example` :

```sh
./korben-dns-relay probe --url https://relay.example:8443 \
  --bootstrap-ip 127.0.0.1 --target 198.41.0.4 --token-file token.hex
```

Le test envoie une question `. NS` non récursive. Ajoutez `--tcp` pour
utiliser TCP du relais à l’autorité. L’IP d’amorçage évite la résolution du
nom du relais ; le nom HTTPS reste utilisé pour vérifier le certificat.
Sans IP explicite, une URL avec un nom dépend du DNS système au démarrage.

## Déploiement

- **Privé, recommandé :** fournissez un jeton et des IP autorisées exactes.
  Sur une machine dédiée, `--allow-any-public` permet de joindre les
  autorités découvertes en cours de récursion. Cette option exige toujours
  un jeton. Bloquez en sortie vos réseaux privés, administratifs et ceux du
  fournisseur, y compris s’ils utilisent des adresses publiques.
  `--deny` accepte des préfixes supplémentaires ; il ne remplace pas le
  pare-feu.
- **Public, limité :** `--public --allow IP1,IP2` autorise ces seules
  destinations sans jeton. Ce mode n’offre pas une récursion générale ;
  autoriser seulement les racines sert à tester le transport. Impossible
  de combiner `--public` et `--allow-any-public`.
- **Réseau :** écoute HTTPS seule. Sur un VPS, exposez TCP 443 et laissez
  sortir UDP/TCP 53 vers les autorités autorisées. Utilisez un compte non
  privilégié ; sur Linux, un service systemd peut accorder uniquement
  `CAP_NET_BIND_SERVICE` pour 443, ou le pare-feu peut rediriger 443 vers
  un port non privilégié. N’ouvrez pas le port 53 en entrée. Le poste client
  ne doit pas ouvrir de port entrant.
- **Certificats :** renouvellement par un outil séparé, puis redémarrage.
  Le relais ne fait pas d’ACME, ne configure pas de proxy et ne change
  aucun réglage DNS ou pare-feu.

## Confidentialité

Aucun journal d’accès, cookie, compte, identifiant d’appareil, historique
DNS, cache partagé ou télémétrie. Les quotas en mémoire portent sur le
débit global et les réseaux de destination, sans table d’IP clientes. Le
relais voit nécessairement l’IP du client et le paquet pendant l’échange.
Le segment du relais aux autorités utilise DNS classique sur le port 53.
L’hébergeur, le système ou un proxy placé devant le relais peuvent garder
leurs propres traces ; vérifiez leur configuration avant de publier une
politique de confidentialité.

[Protocole et intégration](docs/PROTOCOL.md) ·
[Validation du prototype](docs/VALIDATION.md) ·
[Modèle de menace et critères de déploiement](SECURITY.md) ·
[Licence PolyForm Noncommercial](LICENSE)
