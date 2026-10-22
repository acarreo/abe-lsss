# Politiques ABE-LSSS : syntaxe, outillage et génération de test vectors

Ce document décrit comment les **politiques d'accès** (policies) et les **listes
d'attributs** sont formulées dans `abe-lsss`, comment les tester avec l'outil
`abe-policy`, comment interpréter les tests de
[tests/test_policy.cpp](../tests/test_policy.cpp), et comment produire des
*test vectors* pour la partie *access control* (politiques/attributs), en
complément des vecteurs cryptographiques déjà échangés dans
[tests/abe-rs-interop.json](../tests/abe-rs-interop.json).

Il fait suite à un échange préalable sur les test vectors d'interopérabilité
(voir [tests/reunion-abe-shield.txt](../tests/reunion-abe-shield.txt)), dont il
ressort que la couverture de test la plus utile à apporter côté `abe-lsss`
porte sur les politiques et attributs (`rust-cp-long-attribute`,
`rust-cp-nested`, `rust-cp-unsatisfied`, etc.), et non sur les primitives
cryptographiques elles-mêmes, déjà couvertes.

## 1. Deux notions distinctes : politique et liste d'attributs

- Une **politique** (`OpenABEPolicy`, [include/lsss/zpolicy.h](../include/lsss/zpolicy.h))
  est un arbre logique de portes `AND`/`OR`/seuil sur des feuilles qui sont
  soit des attributs nommés, soit des comparaisons (`<`, `>`, `<=`, `>=`, `==`,
  `in`) sur des entiers ou des dates.
- Une **liste d'attributs** (`OpenABEAttributeList`,
  [include/lsss/zattributelist.h](../include/lsss/zattributelist.h)) est un
  ensemble d'attributs concrets détenus par un utilisateur, séparés par `|`.
  Elle peut porter des valeurs numériques ou de date (`Attr=valeur`) mais
  jamais de comparaison (`<`, `>=`, etc. sont interdits dans une liste
  d'attributs).

Selon le schéma :

| Schéma     | Politique attachée à... | Attributs attachés à... |
|------------|--------------------------|---------------------------|
| CP-ABE (`cp-waters`) | Chiffré (ciphertext) | Clé privée de l'utilisateur |
| KP-ABE (`kp-gpsw`)   | Clé privée de l'utilisateur | Chiffré (ciphertext) |

C'est pour cela que dans `abe-rs-interop.json` le champ `policy` et le champ
`attributes` (ou `secret_key`/`master_public_key`) ne jouent pas le même rôle
suivant `scheme`.

## 2. Grammaire des politiques

La grammaire est définie par le parser Bison
[include/lsss/zparser.yy](../include/lsss/zparser.yy) et le lexer
[src/lsss/zscanner.ll](../src/lsss/zscanner.ll). Résumé des constructions
supportées :

### 2.1 Combinateurs booléens

```
Alice
(Alice or Bob)
((Alice or Bob) and (Charlie or David))
((Alice and Bob) or uid:567abc)
```

- `and` / `or` sont les seuls connecteurs supportés en entrée texte (le moteur
  interne supporte aussi des portes à seuil `k-of-n`, mais elles ne sont pas
  exposées par cette grammaire textuelle).
- Les parenthèses sont libres ; l'ordre des opérandes n'a pas d'incidence sur
  l'ensemble d'attributs résultant (`toString()`/`toCompactString()`
  normalisent l'arbre).
- Un attribut peut porter un préfixe `prefix:attribut` (ex: `uid:567abc`),
  séparé par `:`.

### 2.2 Comparaisons numériques

```
Day > 5
Day >= 5
Month == 7#4
Month < 12#4
Level in (2-35)      # borne haute exclusive
Month in {3#4-15#4}  # borne haute inclusive (accolades)
```

- `>`, `<`, `<=`, `>=`, `==` comparent un attribut numérique à un entier.
- La forme `valeur#nb_bits` (« expint ») encode un entier sur un nombre de
  bits fixé, utilisé par le schéma de comparaison LSSS sous-jacent
  (bit-decomposition). `nb_bits` doit être positif et suffisant pour
  représenter la valeur (sinon erreur de parsing, cf. §4).
- `in (a-b)` est un intervalle **borne haute exclusive** ; `in {a-b}` est
  **inclusif**.
- Important : `=` seul n'est **pas** un opérateur de comparaison dans une
  politique numérique — il faut `==` (voir test
  `LinearSecretSharing.TestOtherComparisonOps`, qui vérifie qu'une politique
  avec `Month= 2#4` lève une exception).

### 2.3 Comparaisons et intervalles de dates

```
Date = January 1, 1968
Date > January 5, 2016
Date < January 1, 2017
Date = May 1-10, 2016            # intervalle de jours dans le mois
Date = December 10-16, 2016
```

- Format attendu : `<mois textuel> <jour[,-jour]>, <année>`.
- Les dates sont converties en timestamp Unix ; toute date strictement
  antérieure au 1er janvier 1970 est **rejetée** (`InvalidDate`).
- Les bornes de jour invalides (`0`, `> 31` selon le mois) sont rejetées
  (`InvalidStartDateRange`, `InvalidEndDateRange`).
- Le séparateur entre l'attribut et la date doit être `=`, `<`, `>`, `<=` ou
  `>=` — jamais `:` (`InvalidDateFormat`).

### 2.4 Ce qui est explicitement interdit

- Un attribut brut ne peut pas ressembler à un `expint` interne
  (`foo_expint04_...`) : réservé au moteur, refusé en entrée utilisateur.
- Les entiers négatifs sont interdits dans les `expint` (`Month > -1#4`).
- Un nombre de bits nul ou insuffisant pour la valeur est refusé
  (`Month < 4#0`, `Month < 16#4` avec 4 bits ne pouvant représenter 16).

## 3. Grammaire des listes d'attributs

```
Alice|Bob|Charlie|David
Alice|Charlie|uid:567abcdef
Alice|Date=May 5, 2016
Day=1000#8      # numérique, autorisé
Day >= 100      # INTERDIT dans une liste d'attributs
```

- Séparateur `|`, préfixes optionnels `prefix:attribut`.
- Un attribut numérique ou date s'exprime avec `=` (jamais avec un opérateur
  de comparaison, qui n'a pas de sens pour une valeur concrète détenue par un
  utilisateur).
- Les attributs de date dupliqués dans une même liste sont silencieusement
  dédupliqués.
- La forme `expint` explicite (`Day=1000#8`) est refusée en entrée
  utilisateur pour une liste d'attributs, comme pour les politiques.

## 4. Outil `abe-policy` : tester syntaxe et satisfaction

Le binaire `abe-policy` (compilé depuis [cli/policy.cpp](policy.cpp), cible
CMake définie dans [cli/CMakeLists.txt](CMakeLists.txt)) offre trois
commandes, illustrées par [cli/abe-policy-examples.txt](abe-policy-examples.txt) :

```sh
./abe-policy policy "<politique>"
./abe-policy attributes "<attribut1>|<attribut2>|..."
./abe-policy logic "<politique>" "<attribut1>|<attribut2>|..." [verbose:true|false]
```

- `policy` : parse une politique via `createPolicyTree()`
  ([include/lsss/zpolicy.h](../include/lsss/zpolicy.h)) et affiche sa forme
  développée (`toString()`) et sa forme compacte normalisée
  (`toCompactString()`). Retourne un code d'erreur non nul si le parsing
  échoue (utile pour tester les cas invalides du §2.4).
- `attributes` : parse une liste d'attributs via `createAttributeList()`
  ([include/lsss/zattributelist.h](../include/lsss/zattributelist.h)) et
  affiche ses deux représentations, plus le nombre d'attributs bruts.
- `logic` : parse la politique **et** la liste d'attributs, puis appelle
  `checkIfSatisfied(policy, attrList)`
  ([include/lsss/zlsss.h](../include/lsss/zlsss.h)) qui renvoie
  `pair<bool,int>` : un booléen de satisfaction et le nombre de correspondances
  (« matches ») trouvées dans l'arbre. C'est **le point d'entrée le plus
  pertinent pour générer des vecteurs de test access-control**, car il exerce
  exactement la logique de décision utilisée en amont du LSSS (partage de
  secret) réel utilisé par le chiffrement/déchiffrement.

`checkIfSatisfied` est une vérification logique pure (sans cryptographie) :
elle donne la même réponse booléenne que celle qui déterminerait en pratique
si un déchiffrement CP/KP-ABE réussit (`expect_decrypts` /
`reference_decrypts` dans `abe-rs-interop.json`), mais sans dépendre de
courbes elliptiques, clés ou aléa — ce qui la rend idéale pour des vecteurs de
test **indépendants du langage et de la bibliothèque crypto**.

## 5. Ce que couvre `tests/test_policy.cpp` et pourquoi c'est pertinent

Le fichier [tests/test_policy.cpp](../tests/test_policy.cpp) regroupe trois
familles de tests, qui correspondent chacune à une couche différente :

1. **Parsing / validation syntaxique** (fixture `PolicyParser`) : vérifie que
   `createPolicyTree` / `createAttributeList` acceptent les constructions
   valides (§2, §3) et rejettent explicitement les constructions invalides
   (dates avant 1970, plages de jours incohérentes, séparateur `:` au lieu de
   `=`, `expint` mal formés, entiers négatifs, opérateurs de comparaison dans
   une liste d'attributs, `expint` explicite en entrée utilisateur...). C'est
   la couverture la plus proche de ce qu'il reste à combler côté
   access-control : chaque `ASSERT_TRUE`/`ASSERT_FALSE` correspond à un
   vecteur de test « la politique/l'attribut X doit (ne pas) parser ».

2. **Correction logique du partage de secret (LSSS)** (fixtures
   `LinearSecretSharing` et `LSSS`, fonction utilitaire `runLSSSTest`) :
   pour un `(policy, attrList)` donné, partage un secret aléatoire selon
   l'arbre de politique, puis tente de le reconstituer à partir des parts
   correspondant aux attributs fournis, et vérifie l'égalité. C'est
   l'équivalent *cryptographique* de `checkIfSatisfied` (le composant qui
   fait effectivement échouer/réussir le déchiffrement), utile pour valider
   qu'une politique satisfaite/non satisfaite au sens logique l'est aussi au
   sens du partage de secret (opérateurs numériques, dates, doublons
   d'attributs, arbres déséquilibrés/équilibrés à grande échelle...).

3. **Passage à l'échelle** (`TestCorrectnessOfBalancedAndPolicyTree`,
   `TestCorrectnessOfSkewedAndPolicyTree`) : mêmes vérifications que (2) mais
   sur des arbres générés automatiquement (équilibrés ou en chaîne `AND`) à
   plusieurs centaines/milliers d'attributs, pour couvrir la robustesse du
   parseur et du LSSS aux grandes politiques — moins pertinent pour des
   vecteurs d'interop mais utile à mentionner pour ne pas le dupliquer inutilement.

Pour la démarche de génération de test vectors visée ici, ce sont surtout les
tests de la famille (1) — et dans une moindre mesure (2), pour les cas non
triviaux (numériques, dates, imbriqués, non satisfaits) — qui doivent être
transformés en *test vectors* portables, car ils encodent des règles de
grammaire et de satisfaction indépendantes de l'implémentation.

## 6. Générer des test vectors « access control »

### 6.1 Format proposé

Nous réutilisons le même style de fichier JSON que `abe-rs-interop.json`, mais en
ajoutant un `"kind": "access-control"` distinct des vecteurs `"interop"`
existants, sans nécessiter aucun matériel cryptographique :

```json
{
  "kind": "access-control",
  "name": "cp-nested-satisfied",
  "policy": "Alice and (Bob or (Charlie and Dave))",
  "attributes": "|Alice|Charlie|Dave|",
  "expect_parses": true,
  "expect_satisfies": true
}
```

Champs :

- `name` : identifiant court et explicite (mêmes conventions que les noms
  `rust-cp-*` déjà utilisés).
- `policy` : chaîne de politique telle que passée à `createPolicyTree` /
  `./abe-policy policy "..."`.
- `attributes` : chaîne de liste d'attributs telle que passée à
  `createAttributeList` / `./abe-policy attributes "..."` (peut être omise
  pour un vecteur qui ne teste que le parsing d'une politique invalide).
- `expect_parses` : `true`/`false` — la politique (et la liste d'attributs, le
  cas échéant) doit parser avec succès. Permet d'encoder les cas rejetés du
  §2.4/§3 sans avoir besoin d'un champ `attributes`.
- `expect_satisfies` : `true`/`false`, uniquement pertinent quand
  `expect_parses = true` et que `attributes` est renseigné. Correspond au
  premier élément du `pair<bool,int>` retourné par `checkIfSatisfied`.
- (optionnel) `match_count` : second élément du `pair`, si l'on souhaite aussi
  vérifier le nombre de correspondances trouvées.

Ce format est directement dérivable de deux champs déjà présents dans
`abe-rs-interop.json` (`expect_decrypts` / `reference_decrypts`), mais purgé
de tout le matériel de clé/chiffré : un test « access control » n'a besoin que
de la politique et des attributs pour être rejouable dans n'importe quelle
implémentation (C++, Rust, ou autre), sans dépendre d'un appariement de
courbes elliptiques particulier.

### 6.2 Procédure de génération (manuelle, à partir de l'outil existant)

Pour chaque cas à couvrir (voir §6.3 pour la liste), exécuter :

```sh
# 1. Vérifier le parsing de la politique
./abe-policy policy "<policy>"        # code retour 0/1 => expect_parses

# 2. Vérifier le parsing des attributs (si applicable)
./abe-policy attributes "<attributes>"

# 3. Vérifier la satisfaction logique
./abe-policy logic "<policy>" "<attributes>" true   # verbose=true pour voir le détail
```

Le code de retour et la sortie `Check if satisfied => true|false` donnent
directement les valeurs `expect_parses` / `expect_satisfies` à recopier dans
le fichier JSON. Le mode `verbose=true` affiche aussi les formes normalisées
(`toString`/`toCompactString`), utiles pour vérifier qu'une autre
implémentation (Rust) produit bien la même normalisation si l'on souhaite comparer
au-delà du simple booléen.

### 6.3 Cas à couvrir en priorité

En reprenant les catégories déjà identifiées comme intéressantes
(`rust-cp-long-attribute`, `rust-cp-nested`, `rust-cp-unsatisfied`) et la
couverture de `test_policy.cpp` :

- **Booléen** : `and`/`or` simples, imbriqués, ordre des parenthèses
  indifférent, doublons d'attributs (`Alice or Alice`, `Alice and Alice`),
  arbres non satisfaits (attribut manquant).
- **Attributs longs / préfixés** : attributs > 16 caractères (cf.
  `a-very-long-attribute-name-past-sixteen` dans `abe-rs-interop.json`),
  attributs avec préfixe (`uid:567abc`).
- **Numérique** : `>`, `<`, `>=`, `<=`, `==`, `in (a-b)` (exclusif), `in {a-b}`
  (inclusif), avec et sans `expint` (`#bits`) ; cas d'erreur : bits
  insuffisants, bits nuls, valeur négative, `=` simple refusé sur numérique.
- **Date** : égalité, comparaison, intervalle de jours dans un mois ; cas
  d'erreur : date avant 1970, jour de début/fin hors plage du mois,
  séparateur `:` invalide.
- **Attributs invalides en liste** : opérateur de comparaison dans une liste
  d'attributs (doit échouer), `expint` explicite en entrée utilisateur (doit
  échouer), doublons de dates (doivent être silencieusement dédupliqués,
  donc `expect_parses = true` mais à comparer par forme normalisée plutôt que
  satisfaction).

### 6.4 Génération outillée

Plutôt que de retranscrire manuellement les sorties console (§6.2),
[tests/tools/generate_access_control_vectors.py](../tests/tools/generate_access_control_vectors.py)
automatise la procédure : il déclare la liste des cas `(name, policy,
attributes, expect_satisfies)` en tête de fichier, invoque le binaire
`abe-policy` (`policy` / `attributes` / `logic`) pour chacun, et écrit le
résultat au format du §6.1 dans
[tests/abe-access-control-vectors.json](../tests/abe-access-control-vectors.json).
Il compare aussi la satisfaction obtenue à la valeur attendue déclarée dans le
script et émet un avertissement en cas d'écart, ce qui évite les erreurs de
retranscription.

Pour régénérer le fichier après modification de la liste de cas :

```sh
cmake --build .build --target abe-policy
python3 tests/tools/generate_access_control_vectors.py
```

Le fichier généré contient à ce jour 49 vecteurs, couvrant l'ensemble des
catégories du §6.3 (booléen, attributs longs/préfixés, numérique, date,
listes d'attributs invalides).
