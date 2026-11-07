# TP6 : Pipeline CI/CD sécurisée

## Environnement
- Cluster Kubernetes : k3s (containerd). L'image locale est importée avec `k3s ctr images import` (équivalent de `kind load docker-image`)
- Outils : Docker, Helm 3, Trivy, kubectl, GitHub Actions
- Dépôt : https://github.com/penelopeeckhar/shift-left-k8s-pipeline

## Partie A : Workflow CI et pinning
| Action | Version | SHA (40 caractères) |
|---|---|---|
| actions/checkout | v4.3.1 | 34e114876b0b11c390a56381ad16ebd13914f8d5 |
| azure/setup-helm | v4.3.1 | 1a275c3b69536ee54be43f2070a358922e12c8d4 |
| aquasecurity/trivy-action | 0.35.0 | 57a97c7e7821a5776cebc9bb87c984fa69cba8f1 |

1. `contents: read` applique le moindre privilège : un job compromis ne peut pas modifier le dépôt, contrairement à `write-all`.
2. `persist-credentials: false` évite de laisser le jeton GitHub dans `.git/config`, où une étape ou une action tierce pourrait le lire.
3. Une PR externe contient du code écrit par un tiers, qui peut tenter d'exfiltrer des secrets ou d'abuser des permissions du runner.

## Partie B : Image et Trivy
| Étape | Base | Vulnérabilités (HIGH/CRITICAL, avec correctif) | Décision |
|---|---|---|---|
| Run #1 (rouge) | nginx-unprivileged:1.27-alpine, Alpine 3.21.3 | 65 (62 HIGH, 3 CRITICAL) | Bloqué par le gate : mettre à jour la base |
| Base `stable-alpine` | Alpine 3.24.2 | 10 (9 HIGH, 1 CRITICAL) | Insuffisant : paquets encore en retard |
| + `apk upgrade --no-cache` | Alpine 3.24.2 | 0 | Accepté |

Paquets concernés au départ : openssl (libcrypto3, libssl3), curl/libcurl, libexpat, libpng, libxml2, musl, pcre2, zlib, brotli, tiff, c-ares, nghttp2. Les trois CRITICAL étaient brotli-libs et libcrypto3/libssl3.

1. Un code de sortie non nul signifie que Trivy a trouvé des vulnérabilités au-dessus du seuil. L'étape échoue et le pipeline s'arrête.
2. Sans seuil explicite, le comportement dépend de la configuration par défaut, donc il n'est pas reproductible. Le seuil fait partie de la politique de sécurité.
3. `ignore-unfixed` masque uniquement ce qui n'a pas de correctif. Ces vulnérabilités restent exploitables et demandent un suivi et des mesures compensatoires.
4. Un pipeline vert peut venir d'un seuil trop laxiste. Le run #1 a bloqué une vraie image obsolète : il fallait lire le rapport pour choisir la bonne décision.

## Partie C : Chart Helm
- `helm lint` : OK
- `trivy config` sur `rendered.yaml` : 3 alertes LOW, aucune HIGH/CRITICAL
- Correction de `KSV014` (système de fichiers racine) : `readOnlyRootFilesystem: true` avec un volume `emptyDir` monté sur `/tmp`

1. `values.yaml` contient seulement des paramètres. `rendered.yaml` est ce qui est réellement appliqué au cluster.
2. Le ServiceAccount est l'identité du Pod face à l'API Kubernetes.
3. Sans jeton monté, un attaquant qui compromet le conteneur n'a aucun identifiant pour interroger l'API.
4. `helm lint` vérifie la syntaxe et les bonnes pratiques. `helm template` produit les manifests finaux. `trivy config` détecte les mauvaises configurations de sécurité.

## Partie D : Déploiement
- Premier déploiement en `ImagePullBackOff` : le cluster est k3s, donc `kind load` ne s'applique pas. Solution : `docker save | sudo k3s ctr images import -`
- Après un arrêt de la VM, les pods sont restés bloqués (`FailedCreatePodSandBox`, erreur 429 du plugin réseau du cluster). Solution : désinstaller et réinstaller la release Helm
- Test final : `curl -I` renvoie `HTTP/1.1 200 OK`

1. Un Pod exécute les conteneurs. Un Deployment gère les ReplicaSets et donc le nombre et les mises à jour des Pods. Un Service donne une adresse stable.
2. Le sélecteur `app: web` relie le Service aux Pods portant ce label.
3. Non. `ClusterIP` n'est accessible qu'à l'intérieur du cluster.

## Partie E : RBAC
| Vérification | Résultat |
|---|---|
| tp-deployer : get deployments | yes |
| tp-deployer : create deployments | yes |
| tp-deployer : delete namespaces | no |
| tp-deployer : create clusterroles | no |
| web : get secrets | no |
| web : get pods | no |
| web : list secrets | no |

1. `cluster-admin` donne un contrôle total : en cas de compromission, tout le cluster est touché.
2. Un Role s'applique à un namespace, un ClusterRole à tout le cluster.
3. Un RoleBinding accorde des droits dans un namespace, un ClusterRoleBinding sur tout le cluster.
4. L'application et le déploiement ont des besoins différents : l'application n'a pas à créer de ressources.
5. Non. `--as` vérifie l'autorisation (RBAC), pas l'authentification ni la validité d'un jeton.

## Partie F : Durcissement du Pod
Vérifié dans le YAML du Pod : `runAsNonRoot: true`, `runAsUser: 101` (`id` renvoie `uid=101(nginx)`), `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `readOnlyRootFilesystem: true`, `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`, `serviceAccountName: web`, requests 50m/64Mi et limits 250m/128Mi.

| Configuration | Résultat Trivy |
|---|---|
| Sécurisée | 3 LOW |
| Affaiblie (`runAsNonRoot: false`, `allowPrivilegeEscalation: true`) | 3 LOW + 2 MEDIUM : <identifiants KSV> |

Le seuil initial `CRITICAL,HIGH` ne détectait pas cette régression. Je l'ai donc étendu à `MEDIUM` pour le scan des manifests.

1. Un processus root compromis a plus de droits : accès aux fichiers sensibles, risque d'évasion, modification du système.
2. `allowPrivilegeEscalation: false` empêche un processus d'obtenir plus de privilèges que son parent (setuid, etc.).
3. Chaque capability inutile est une surface d'attaque supplémentaire.
4. Non. Les limites ne protègent pas contre un déni de service réseau ni contre l'épuisement d'autres ressources.
5. Trivy détecte après coup (analyse statique). Empêcher l'admission demande un contrôleur d'admission (Pod Security Admission, Kyverno, OPA Gatekeeper) qui refuse la ressource à la création.

## Partie G : Workflow et quality gate
- Run #1 : échec à l'étape Scan image (65 vulnérabilités). Le gate a bloqué une image obsolète
- Run #2 : succès après correction du Dockerfile
- Test de la section 9.1 : PR avec `runAsNonRoot: false`, échec attendu à l'étape Scan Kubernetes manifests <à confirmer avec ta capture>

Les constructions CI et locale utilisent le même Dockerfile mais des tags différents. Cela valide la recette de construction, pas l'identité binaire de l'artefact.

### Architecture (9.2)
Avant d'autoriser un pipeline distant à déployer : identité fédérée OIDC sans secret statique, RBAC limité au namespace, environnements séparés avec des identités distinctes, approbation manuelle avant la production, protection des secrets et runners éphémères non partagés, journalisation et capacité de révocation rapide.

## Partie H : Action tierce compromise
1. Frontières franchies : de l'action tierce non fiable vers le job CI, puis vers le registre, le cloud et le cluster.
2. Dommages : dépôt (code et secrets lus), registre (image empoisonnée via `packages: write`), cluster (déploiement malveillant via l'identité trop privilégiée).
3. Mesures du chapitre : pinning par SHA, permissions minimales, `persist-credentials: false`, scans bloquants, RBAC limité.
4. Un compte limité réduit le rayon d'impact à un namespace et à quelques ressources.
5. Mesures immédiates : révoquer et faire tourner les secrets, isoler le runner, analyser les journaux, redéployer depuis un état connu et sain.

## Limites
Les tags d'image (`stable-alpine`, `local`) ne sont pas immuables. En production, référencer l'image de base par digest, avec signature et provenance (chapitre 7).
