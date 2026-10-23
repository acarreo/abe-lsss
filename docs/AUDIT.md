# Audit de `abe-lsss` — Phase 0

**Date :** 22 octobre 2026
**Révision inspectée :** `ac0b5fd` (`main`)
**Périmètre :** inspection statique de `abe-lsss`, comparaison de structure avec le dépôt local `openabe` et examen du patch d’intégration de `secure-file-transfer`. Aucun code cryptographique n’a été modifié. Cet audit n’est pas un audit cryptographique indépendant ni une validation formelle des preuves de sécurité.

> **Repère temporel :** les constats ci-dessous décrivent l’état inspecté à `ac0b5fd`. Ils ne décrivent pas tous l’état actuel du dépôt. Le suivi des corrections des phases 2 et 3 est ajouté à la fin; les observations initiales sont conservées comme photographie historique.

## Synthèse

`abe-lsss` est une adaptation C++ d’OpenABE qui conserve une grande partie de ses noms, de ses abstractions et de son code de bas niveau, tout en séparant le cœur ABE/LSSS, les schémas, le CLI et le build CMake. Les deux schémas ABE que la fabrique construit effectivement sont CP-ABE de Waters et KP-ABE de Goyal–Pandey–Sahai–Waters. La base comporte aussi des composants de chiffrement symétrique, de chiffrement à clé publique et de signature hérités, mais leur présence ne signifie pas que des variantes CCA-ABE ou multi-autorités soient disponibles.

Points prioritaires relevés à la révision auditée :

1. Les sources des deux schémas sont compilées séparément dans les exécutables CLI/tests/bench, mais ne figurent pas dans les sources de la bibliothèque `abe_lsss` définies au CMake racine. L’API installée peut donc ne pas fournir ces implémentations à un consommateur qui ne les recompile pas.
2. La configuration locale `.build` a `TESTS=OFF`; `ctest` y trouve zéro test. La CI demande `TESTS=ON`, mais il n’y a qu’un workflow Linux.
3. Des noms et contrats d’API OpenABE subsistent. Les fonctions de contexte CCA sont désactivées par `#if 0`, malgré des identifiants CCA conservés.
4. Les indicateurs de compression et d’état global sont globaux, et l’effacement de secrets / le comportement multi-thread ne sont pas garantis de bout en bout par la documentation ou des tests dédiés.
5. L’option `RELIC_TAG` transmise par `compile/Makefile` est écrasée par la valeur fixe dans `compile/install-relic.sh`.

## Cartographie des dossiers

| Dossier | Rôle observé |
|---|---|
| `src/` | Cœur hérité : `src/abe/` contient API/contextes, KDF, keystore, primitives symétriques, PKE et signatures; `src/lsss/` contient objets, attributs, parser/scanner générés, wrappers de groupes et partage/récupération LSSS. |
| `include/` | En-têtes publics organisés en `include/abe/` et `include/lsss/`; `include/abe_lsss.h` est l’en-tête parapluie qui expose une API très large. |
| `schemes/` | Implémentations CP-ABE Waters et KP-ABE GPSW, plus `abecontext.cpp`, la fabrique qui instancie ces deux schémas. |
| `cli/` | Exécutables setup, keygen, encrypt, decrypt et policy; exemples et scripts de test manuel/fuzz superficiel. L’installation des exécutables est commentée dans son CMake. |
| `bench/` | Benchmarks Google Benchmark de schémas ABE et de politiques; générateurs de politiques, script d’exécution et image de résultats existante. |
| `tests/` | Tests GoogleTest, jeu de vecteurs JSON et générateur de vecteurs. Le CMake de tests ne déclare pas tous les fichiers de test présents. |
| `utils/` | Types/identifiants de schémas, conversion d’identifiants, construction d’entrées fonctionnelles et utilitaires partagés. |
| `compile/` | Makefile et scripts pour installer RELIC et éventuellement mettre à niveau GCC. |
| `docker/` | Dockerfiles RELIC et abe-lsss, Makefile et instructions d’image. |
| `.github/` | Un workflow GitHub Actions CMake sur `ubuntu-latest`, déclenché sur push/PR vers `main`. |
| `docs/` | Absent avant cet audit; ce document crée le dossier. |

Le répertoire `.build/` existant est un répertoire de travail généré, ignoré par Git; il ne fait pas partie de la cartographie des sources.

## Diff conceptuel avec OpenABE

| Sujet | Observation dans `abe-lsss` par rapport à `openabe` |
|---|---|
| Organisation | OpenABE regroupe des composants sous `src/abe`, `src/tools`, `src/zml`, `src/utils` et fournit un arbre d’en-têtes `src/include/openabe`. Ici, les en-têtes sont dans `include/abe` et `include/lsss`, le code de pairing dans `src/abe`/`src/lsss`, et les schémas dans `schemes/`. Le build a été remplacé par CMake + scripts dédiés RELIC/Docker. |
| LSSS | LSSS n’est pas nouveau par rapport à OpenABE : les deux dépôts en possèdent une implémentation. `abe-lsss` conserve la logique LSSS et le parser de politiques, avec des en-têtes et sources déplacés/séparés sous `include/lsss` et `src/lsss`, et un wrapper RELIC de groupes de pairing. |
| Schémas | La fabrique locale `createContextABE` n’instancie que `CP_WATERS` et `KP_GPSW`. Les composants hérités PKE, SKE et signature sont toujours présents dans `src/abe`, mais ne constituent pas des schémas ABE supplémentaires. |
| CCA | Des valeurs `CP_WATERS_CCA` et `KP_GPSW_CCA` existent dans l’énumération. En revanche, `zcontextcca.h` et `zcontextcca.cpp` placent les classes et leur implémentation sous `#if 0`; les fonctions de création de contextes CCA visibles dans l’API sont commentées, et la fabrique ABE n’accepte que les identifiants CPA. |
| Multi-autorité | Des types et paramètres hérités (`MA-ABE`, GPK, GID) restent dans les interfaces communes. Aucun schéma multi-autorité n’est enregistré dans la fabrique observée. |
| API | À la révision auditée, les fonctions `InitializeOpenABE()` / `ShutdownOpenABE()`, les types `OpenABE*`, les identifiants de schéma et les messages d’erreur OpenABE étaient conservés. Le suivi ci-dessous décrit la nouvelle façade et les alias de compatibilité. |
| Sérialisation et compression | La sérialisation des éléments de `ZP`, `G1`, `G2` et `GT` est conservée. `set_compression_flag(0|1)` contrôle globalement le paramètre transmis à RELIC pour les représentations de groupes; le défaut est compressé. Ce réglage global n’est pas attaché à un contexte ni à un format/version de sérialisation documenté ici. |
| Éléments absents ou non retrouvés | Le dépôt OpenABE local contient aussi des modules dédiés RNG, courbes EC additionnelles, X.509, fuzzers et outils/profileurs. Leurs équivalents ne sont pas présents dans les répertoires source de `abe-lsss` inspectés. Cela ne prouve pas une suppression intentionnelle de chaque fonctionnalité, mais le périmètre livré est plus réduit. |
| Intégration consommateur | `secure-file-transfer/scripts/abe-lsss.patch` ajoute notamment un mode CP-Waters à déchiffrement partiel (`CP_WATERS_WPD`), `partialDecrypt` et `randomizeDecryptionKey`, ainsi qu’un identifiant IBS. Ces ajouts ne sont pas dans la fabrique/schéma actuel d’`abe-lsss`; ils requièrent donc une compatibilité explicite ou l’application de ce patch dans le consommateur. |

## Schémas ABE et propriétés de sécurité

Les niveaux ci-dessous distinguent la construction que l’API expose de la preuve du papier. La correspondance complète entre les équations du code, les hypothèses du papier et le modèle de sécurité n’a pas été auditée.

| Schéma réellement instancié | Fonctionnement | Sécurité exposée | Modèle de sécurité de la référence | Référence / remarque |
|---|---|---|---|---|
| CP-ABE Waters | Les attributs sont portés par la clé utilisateur; la politique est portée par le chiffré. | CPA via `createContextABESchemeCPA`; aucun contexte CCA ABE actif n’est fourni par la fabrique actuelle. La résistance à la collusion fait partie de la construction ABE visée, mais n’a pas été vérifiée cryptographiquement ici. | La référence Waters 2011 est une construction adaptativement sécurisée; le dépôt ne documente pas le jeu de sécurité ni ne démontre que la variante codée et ses paramètres correspondent exactement à cette preuve. | Brent Waters, “Ciphertext-Policy Attribute-Based Encryption: An Expressive, Efficient, and Provably Secure Realization”, PKC 2011. Les commentaires du code sont incohérents : l’en-tête indique Waters ’09 et l’implémentation Waters ’11; clarifier la source exacte. |
| KP-ABE GPSW | La politique est portée par la clé utilisateur; les attributs sont portés par le chiffré. | CPA via `createContextABESchemeCPA`; pas de contexte CCA ABE actif. Résistance à la collusion attendue de la construction, non auditée indépendamment. | Sécurité sélective dans la construction de référence; le code ne spécifie pas ses paramètres ni son jeu de sécurité. | Vipul Goyal, Omkant Pandey, Amit Sahai et Brent Waters, “Attribute-Based Encryption for Fine-Grained Access Control of Encrypted Data”, ACM CCS 2006; commentaires du code citent également PTMW 2006. |
| ABE multi-autorité | Non instancié. | Non disponible dans la fabrique, même si des identifiants/champs hérités existent. | Sans objet pour le code disponible. | Aucun schéma multi-autorité vérifié dans le dépôt. |
| CP/KP-ABE CCA | Non instancié par la fabrique actuelle; l’implémentation générique CCA de ce dépôt est désactivée par préprocesseur. | Ne pas présenter comme CCA. | Sans objet pour le code actif. | Les identifiants CCA conservés dans `utils/common.h` ne constituent pas une implémentation. |

Les policies LSSS sont construites comme des arbres monotones (AND/OR/seuils) pour le partage/récupération. Le parser et les tests contiennent aussi des expressions de dates et d’entiers/ranges. Il ne faut pas déduire la prise en charge de politiques non monotones de la seule énumération de types de portes (`NOT`, `NAND`, etc.) : leur traduction et leur prise en charge cryptographique n’ont pas été démontrées par les tests observés.

## Problèmes et risques repérés à la révision auditée

### Build, intégration et maintenance

- **Implémentations ABE absentes de la target bibliothèque — impact élevé.** Le CMake racine inclut `src/abe/*.cpp`, `src/lsss/*.cpp` et `utils/utils.cpp`, mais pas `schemes/*.cpp`. Les CMake de CLI, tests et bench recompilent explicitement `schemes/zcontextcpwaters.cpp`, `schemes/zcontextkpgpsw.cpp` et `schemes/abecontext.cpp`. Vérifier que la cible installée fournit réellement les symboles attendus par un consommateur externe.
- **Options de tests ambiguës.** `TESTS` est l’option exposée; `BUILD_TESTS` est lu mais pas déclaré par un `option()` dédié. La CI configure `-DTESTS=ON`, tandis que le répertoire de build local audité a `TESTS=OFF`.
- **Installation liée à `/usr/local`.** Le CMake d’installation utilise un chemin de destination absolu et un `install(CODE)` qui lit/écrit `/usr/local/include/...`; cela ne respecte pas proprement un `CMAKE_INSTALL_PREFIX` personnalisé.
- **`RELIC_TAG` inopérant dans le Makefile compile.** `compile/Makefile` transmet `RELIC_TAG` à `install-relic.sh`, mais ce script réinitialise la variable à `0.6.0`. L’installation manuelle documentée ne permet donc pas réellement de sélectionner une autre version avec cette option.
- **Dépendance RELIC épinglée à 0.6.0.** Le CMake de secours utilise `GIT_TAG 0.6.0`; l’installation scriptée pointe aussi sur cette version. Les niveaux de sécurité/courbes doivent être documentés par courbe et revalidés avant mise à jour.
- **CI étroite.** Un seul job Linux, sans matrice GCC/Clang, macOS, sanitizers, format, analyse statique ni couverture.
- **Code hérité/incohérences.** Le nommage OpenABE traverse API, classes, commentaires et messages; les références Waters ’09/’11 divergent. Les fichiers `tests/test_pke.cpp` et certains utilitaires présents ne sont pas enregistrés dans `tests/CMakeLists.txt`.

### Sécurité et robustesse

- **État global et concurrence.** `compression_flag` et `gLibraryState` sont globaux et non atomiques. Une modification concurrente de compression, une initialisation/shutdown concurrente ou des usages RELIC multi-thread doivent être spécifiés et testés. Les wrappers `OpenABEStateContext` existent, mais leur cycle de vie ne remplace pas une preuve globale de thread-safety.
- **Aléatoire.** Les schémas sollicitent `OpenABEPairing::randomZP/G1/G2`, qui s’appuie sur RELIC. Aucune injection d’interface RNG ni audit de l’initialisation/entropie en production n’a été identifié dans ce périmètre.
- **Effacement des secrets partiel.** Certaines classes appellent `zeroize()` et certaines données utilisent `OPENSSL_cleanse`, mais les valeurs RELIC et temporaires ne bénéficient pas d’une garantie uniforme de destruction sécurisée observée. Les `memset` ordinaires ne garantissent pas à eux seuls l’effacement après optimisation.
- **Canaux auxiliaires.** Les opérations de groupe sont déléguées à RELIC; aucune analyse de temps constant de bout en bout des chemins ABE, parsing et erreurs n’est fournie. Les comparaisons des éléments de groupe et les chemins dépendant d’attributs doivent être revus.
- **Gestion d’erreurs hétérogène.** Le code mélange codes d’erreur, exceptions, assertions et retours `nullptr`. Certaines branches journalisent ou avalent l’erreur; `ro_error()` affiche un message puis appelle `exit(0)`, ce qui transforme une erreur en sortie apparemment réussie. Les exceptions génériques du parseur et le comportement d’échec de déchiffrement demandent une clarification de contrat.
- **Gestion mémoire.** `unique_ptr` est utilisé dans plusieurs factories/contextes, mais les arbres de politiques, éléments et interfaces héritées conservent des pointeurs bruts et de la gestion manuelle. Les chemins d’échec et la destruction des secrets méritent une vérification dédiée.
- **Désérialisation.** Les API exposent des opérations de désérialisation, mais aucun fuzzer de clés/chiffrés n’est déclaré côté `abe-lsss`; valider bornes, intégrité des structures et rejet d’éléments de groupe invalides.
- **Compatibilité du consommateur.** Le patch `secure-file-transfer` étend explicitement le comportement de schéma/API et ne s’applique pas à l’état courant sans adaptation. Le vérifier avant toute modification de signatures publiques ou de sérialisation.

### Licence

Le dépôt distribue une licence AGPL-3.0 et les fichiers hérités conservent des avis de copyright/attribution Zeutro/OpenABE. Aucun conflit n’a été établi pendant cet audit. Toute redistribution ou évolution doit conserver ces mentions et être examinée au regard des obligations AGPL; cet audit ne constitue pas un avis juridique.

## État initial du build, des tests et de la CI (révision auditée)

- **CMake :** version minimale déclarée 3.10, C++20, OpenSSL et GMP requis. Si RELIC n’est pas trouvé, CMake configure un `ExternalProject` RELIC 0.6.0 sur la courbe `RELIC_CURVE` (défaut `bls12-381`). CLI activé par défaut; benchmarks désactivés par défaut et requièrent Google Benchmark.
- **Makefile RELIC :** `compile/Makefile` annonce `CURVE` et `RELIC_TAG`, mais l’override de `RELIC_TAG` est écrasé dans le script shell.
- **Docker :** deux Dockerfiles (RELIC et abe-lsss) avec Makefile et paramètres documentés `CURVE`, `RELIC_TAG` et `ABE_LSSS_VERSION`. Aucun build Docker n’a été exécuté pendant cet audit.
- **Configuration locale observée :** `.build/CMakeCache.txt` indique `RELIC_CURVE=bls12-381`, `CLI=ON`, `BENCH=ON`, `TESTS=OFF`. Des bibliothèques RELIC et abe-lsss et exécutables CLI/bench sont présents dans ce répertoire.
- **Tests exécutés :** `ctest --test-dir .build --output-on-failure` retourne avec succès mais rapporte **“No tests were found!!!”**. Ce résultat décrit cette configuration locale; il ne prouve ni l’échec ni la réussite des tests activés par la CI.
- **CI :** le workflow installe RELIC, configure `-DTESTS=ON -DBENCH=OFF -DCLI=ON`, build, installe puis appelle CTest sur `ubuntu-latest`. Aucune preuve de build CI réussie n’a été consultée dans cet audit.

## Couverture et zones non testées (révision auditée)

L’estimation de couverture du code est **indisponible** : aucun outil/rapport de couverture n’est configuré ou présent. Sept exécutables de tests sont déclarés par `tests/CMakeLists.txt` (demo, keystore, ABE, policy, SKE, symétrique, bytestring), mais aucun n’est activé dans le build local observé.

Les tests présents couvrent des exemples CPA CP/KP, le keystore, la sérialisation de quelques objets, des primitives SKE/symétriques et le parseur (incluant des expressions date/entier). Un fichier de test PKE est présent mais pas ajouté au CMake des tests. Les vecteurs JSON disposent d’un générateur, mais leur exécution en tant que suite de conformité n’est pas démontrée.

Zones non couvertes ou non démontrées : tests négatifs systématiques de déchiffrement/politiques et de collusion multi-utilisateur; vecteurs cryptographiques publiés; désérialisation malformée et fuzzing; limites de taille/profondeur des policies; concurrence; effacement observable des secrets; non-régression de sérialisation compressée/décompressée; compatibilité `secure-file-transfer`; couverture instrumentée et tests macOS.

## Priorisation initiale (impact × effort)

| Priorité | Sujet | Impact | Effort estimé | Motif |
|---|---|---:|---:|---|
| P0 | Inclure/linker les implémentations ABE dans la bibliothèque installée et tester un consommateur externe minimal | Très élevé | Faible à moyen | Peut rendre l’API ABE annoncée inutilisable hors des exécutables qui recompilent les sources de schéma. |
| P0 | Activer les tests dans une configuration propre et confirmer que la CI les découvre/exécute | Très élevé | Faible | Aujourd’hui, le build local de référence n’exécute aucun test. |
| P1 | Revue cryptographique des implémentations Waters/GPSW, paramètres RELIC, RNG et assertions sur la sécurité CPA/CCA | Très élevé | Élevé | Confirmer l’alignement entre code, papiers et modèles de sécurité avant toute revendication. |
| P1 | Revue de sérialisation/désérialisation, fuzzing et tests négatifs de policies, clés et chiffrés | Élevé | Moyen à élevé | Réduit le risque de parsing invalide, corruption et comportements d’échec ambigus. |
| P1 | Clarifier concurrence, durée de vie RELIC et effacement des secrets | Élevé | Moyen à élevé | Les variables globales et buffers/secrets exigent un contrat et des tests ciblés. |
| P1 | Vérifier l’intégration `secure-file-transfer` et documenter la compatibilité du patch WPD | Élevé | Moyen | Préserve le consommateur existant et évite les divergences de schéma/API. |
| P2 | Corriger `RELIC_TAG`, chemins d’installation et options CMake; ajouter build reproductible | Moyen | Faible à moyen | Fiabilise la consommation, l’installation sous préfixe et la mise à jour des dépendances. |
| P2 | Ajouter matrice Linux/macOS et GCC/Clang, sanitizers, couverture et analyse statique | Moyen à élevé | Moyen | Améliore la détection de régressions et la confiance dans les plateformes réellement annoncées. |
| P3 | Réduire/moderniser l’API héritée en conservant des alias documentés | Moyen | Élevé | Améliore lisibilité et intégration, mais risque de compatibilité publique à gérer. |

## Validation de cette phase

- Fichier créé : `docs/AUDIT.md`.
- Aucun code cryptographique, OpenABE ou `secure-file-transfer` n’a été modifié.
- Commande de test exécutée : `ctest --test-dir .build --output-on-failure`; résultat : zéro test découvert car `TESTS=OFF`.
- Aucun commit n’est créé pendant cette phase; commit atomique proposé : `docs(audit): add phase 0 repository audit`.

**Reste / risques :** confirmer les conclusions cryptographiques avec une revue spécialisée; réconcilier les références Waters du code; exécuter le build CI dans un environnement propre; valider le linkage de la bibliothèque auprès d’un client externe; préserver la compatibilité du patch `secure-file-transfer`.

Au moment de l’audit, la Phase 1 (README et guides `docs/`) restait en attente de validation; elle a depuis été réalisée.

## Suivi après les phases 2 et 3 — 23 octobre 2026

Ce suivi complète l’audit initial sans en réécrire les observations historiques. Il se fonde sur les commits `ff8a324` (API et packaging) et `f4ccdf0` (CI et documentation sécurité), ainsi que sur une validation locale de ces commits.

| Sujet initial | État actuel observé |
|---|---|
| Sources ABE absentes de la bibliothèque partagée | Corrigé : CP-Waters, KP-GPSW et leur fabrique sont inclus dans `abe_lsss`. CLI, tests et benchmarks consomment maintenant la bibliothèque au lieu de compiler ces schémas séparément. |
| API ABE non disponible à l’installation | Corrigé pour l’usage documenté : installation des en-têtes, export CMake (`find_package(abe-lsss)` / `abe-lsss::abe_lsss`) et fichier pkg-config. Des consommateurs CMake et pkg-config ont été compilés et exécutés depuis une installation temporaire. |
| API héritée uniquement | Façade `abe_lsss` ajoutée pour le cycle de vie, la compression, la fabrique CP-ABE/KP-ABE et le parsing. Les fonctions d’initialisation/compression OpenABE restent présentes comme interfaces dépréciées; les classes et types internes ne sont pas tous renommés. |
| Tests locaux non activés | CMake découvre maintenant huit exécutables de tests avec `TESTS=ON`. Le build local et CTest passent : 8/8 exécutables. |
| CI Linux seule | Workflow élargi à Linux GCC et Linux Clang; le job ASan/UBSan Linux exécute les tests, puis deux contrôles LeakSanitizer ciblés. Le job macOS a été retiré: le build macOS (assembleur x64 RELIC ELF, en-têtes Flex système) n’a jamais abouti et reste à traiter. |
| Fuites mémoire dans la sérialisation | La propriété RAII des buffers `getBytes()` utilisés par la sérialisation et du buffer hashé pour la dérivation de clé a été corrigée. Les deux tests LeakSanitizer ciblés réussissent. |
| Gestion d’état global | L’état du cycle de vie est atomique et les transitions initialize/shutdown sont protégées par mutex. Cela ne garantit pas qu’un shutdown concurrent à des opérations RELIC soit sûr et ne constitue pas une garantie générale de thread-safety. |
| Sécurité non documentée | `SECURITY.md` et `docs/SECURITY_MODEL.md` décrivent désormais le signalement, les hypothèses et les limitations. |

**Résultats et limites de validation :**

- Build standard local et CTest : 8/8 exécutables passent.
- Build ASan/UBSan et CTest : 8/8 exécutables passent avec la détection de fuites générale désactivée. Cette détection reste désactivée car d’autres tests produisent encore des rapports LeakSanitizer; les deux tests ciblés activent séparément LeakSanitizer et passent.
- Installation temporaire : consommateurs CMake et pkg-config compilés et exécutés.
- Workflow YAML validé syntaxiquement localement; aucun résultat CI distant ni build macOS n’a été consulté.

**Reste / risques :** revue cryptographique indépendante, fuzzing continu de désérialisation (des tests de troncature/altération existent désormais), tests TSan, effacement sûr exhaustif, garantie de thread-safety RELIC, couverture et analyses statiques demeurent à traiter. L’intégration avec le patch `secure-file-transfer` n’a pas été exécutée; le patch n’a pas été modifié.

## Suivi — 24 octobre 2026

- **CI :** réparée sur Linux (GCC, Clang, ASan/UBSan); les builds activent `-D_GLIBCXX_ASSERTIONS`. macOS retiré (non fonctionnel).
- **Correctifs trouvés par les nouveaux tests de robustesse :** `getInternalPtr()` sur buffer vide (comportement indéfini); `exit()` dans les constructeurs `G1`/`G2`, la division `ZP` et `OpenABEAttributeList` remplacés par des exceptions `OpenABE_ERROR`; déréférencement nul dans `decryptKEM` (CP-Waters et KP-GPSW) lorsque la politique d’un chiffré est altérée.
- **Propriété documentée :** les contextes CPA n’authentifient pas les chiffrés (malléabilité), voir `docs/SECURITY_MODEL.md`.
- **`RELIC_TAG` :** `compile/install-relic.sh` respecte désormais la variable d’environnement.
- **Reste :** fuites mémoire (LeakSanitizer général toujours désactivé), revue cryptographique indépendante, intégration `secure-file-transfer`, support macOS.
