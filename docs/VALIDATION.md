# Validation initiale — 8 novembre 2026

Exécutée avec Go 1.27.3. Ce sont des contrôles du prototype, pas une
certification ou un audit externe.

- `go test -race -count=1 ./...` et `go vet ./...` réussis.
- Fuzzing de l’enveloppe et des questions DNS : 3 108 250 exécutions
  en 30 secondes, aucun échec.
- Analyse avec `govulncheck` v1.9.0 du code source et du binaire
  macOS ARM64 : aucune vulnérabilité connue détectée.
- Tests locaux : TLS et nom vérifiés, IP d’amorçage, HTTP sans fuite
  vers un proxy d’environnement, refus avant émission, quotas,
  réponses falsifiées, troncature UDP, lectures TCP fragmentées
  et annulation. Échanges avec une autorité simulée sur les sockets
  UDP et TCP IPv4 et IPv6.
- Binaire macOS ARM64 exécuté. Certificat de test validé par le client
  sans changer la confiance système. Deux requêtes publiques `. NS`
  ont traversé le relais HTTPS vers A-root : 13 enregistrements NS, AA et NOERROR,
  en UDP et en TCP. Arrêt propre et aucune ligne de journal pendant
  l’essai. HTTP/2 confirmé sur un refus d’accès sans jeton.
- Compilations réussies pour macOS, Linux et Windows, en ARM64 et x86-64.
  Windows et Linux restent à tester en exécution native.

Le parcours complet dans KORBEN DNS avec le port 53 bloqué côté client
n’a pas été testé : il nécessite le raccordement d’Unbound décrit dans
[le protocole](PROTOCOL.md).
