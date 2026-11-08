# Sécurité

## Frontières de confiance

Le client vérifie TLS et refuse les redirections et les proxys
d’environnement. Il peut joindre une IP numérique sans rechercher le
nom HTTPS au préalable. La plateforme peut néanmoins faire des accès
réseau pour la validation de certificats ; utilisez une chaîne complète
et testez le démarrage à froid sur le réseau visé.

Le relais n’est pas un résolveur ni une preuve d’autorité. Il peut voir
les requêtes, et un opérateur malveillant peut les supprimer ou fausser
les réponses. DNSSEC vérifié dans Unbound aide pour les données signées ;
il ne protège pas les zones non signées et ne prouve pas que les adresses
de délégation sont autorisées. Voir [RFC 4035 §2.2](https://www.rfc-editor.org/rfc/rfc4035.html#section-2.2).
Pour cacher l’IP au serveur qui lit la requête, une évolution distincte
pourrait utiliser [Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
avec deux opérateurs indépendants.

## Garde-fous et limites

- TLS avant toute requête. Jeton de 256 bits généré aléatoirement, valeur
  comparée via un condensat en temps constant. Pas de jeton public intégré.
- Requête limitée et validée avant tout envoi. Port 53, IP numérique sans
  résolution ni redirection, filtrage des plages spéciales
  [IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/)
  et [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/).
  Les adresses de la machine au démarrage sont exclues ; le pare-feu doit
  aussi tenir compte des changements de réseau, du NAT, des réseaux du
  fournisseur et des routes VPN.
- Socket UDP connecté avec port source attribué par le système, ID
  aléatoire à chaque envoi et contrôle de la question renvoyée
  ([RFC 5452](https://www.rfc-editor.org/rfc/rfc5452.html)).
  Le relais ne répond jamais en UDP côté client. Une requête refusée ne
  produit aucun trafic vers sa destination.
- Serveur : 128 connexions simultanées, huit flux HTTP/2 par connexion,
  32 travaux actifs et délai sortant de trois secondes. Quotas de
  60 requêtes/s globalement (rafale 30) et de 12/s par réseau cible
  IPv4 /24 ou IPv6 /48 (rafale 12). Les compteurs de destination sont
  éphémères et bornés ; aucun identifiant client. Ces limites protègent
  les ressources, mais ne garantissent ni équité entre clients ni
  disponibilité sous attaque distribuée.
- Une destination sur le port 53 n’est pas forcément un serveur DNS
  autoritatif. Un proxy non authentifié vers toute IP publique permet
  scans et saturation ; il est interdit dans le prototype. Voir
  [RFC 9298 §7](https://www.rfc-editor.org/rfc/rfc9298.html#section-7).

## Avant une instance officielle

Utiliser une VM dédiée avec sortie UDP/TCP 53 filtrée, sans réseau
d’administration accessible. Préférer un VPS à un Worker qui expose des
[sockets sortants TCP avec restrictions](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/#considerations).
Vérifier que le port 53 en sortie fonctionne depuis cet hébergeur,
contrôler les journaux d’infrastructure et la configuration TLS.

Pour offrir le service à tous en conservant la récursion locale, démarrer
avec une inscription et des jetons individuels révocables, des quotas
par jeton, des limites de charge et une procédure d’arrêt. Ce système
d’inscription n’est pas dans le prototype. Tester aussi un service
public restreint à des autorités convenues ; sa couverture est
nécessairement limitée. Un DoH récursif distant serait une autre
architecture, avec un autre compromis de confiance.

Faire relire le code et la configuration par une personne indépendante
avant exposition générale. Exécuter `go test -race ./...`, `go vet ./...`,
le fuzzing `go test ./relay -fuzz=FuzzFrame -fuzztime=30s`, et
`govulncheck ./...` avec une version Go supportée. Avant toute publication
de binaires, analyser aussi les binaires, exécuter les tests sur chaque
OS et éprouver les quotas, l’authentification, les délais et l’absence
d’émission directe depuis l’application. Le code source public facilite
ces vérifications ; il ne prouve pas le comportement d’une instance.

Signalez une faille par un canal privé à l’éditeur de KORBEN DNS avant
de publier des détails exploitables.
