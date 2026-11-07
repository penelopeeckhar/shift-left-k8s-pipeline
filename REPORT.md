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
| Affaiblie (`runAsNonRoot: false`, `allowPrivilegeEscalation: true`) | 3 LOW + 2 MEDIUM : KSV-0001, KSV-0012 |

Le seuil initial `CRITICAL,HIGH` ne détectait pas cette régression. Je l'ai donc étendu à `MEDIUM` pour le scan des manifests.

1. Un processus root compromis a plus de droits : accès aux fichiers sensibles, risque d'évasion, modification du système.
2. `allowPrivilegeEscalation: false` empêche un processus d'obtenir plus de privilèges que son parent (setuid, etc.).
3. Chaque capability inutile est une surface d'attaque supplémentaire.
4. Non. Les limites ne protègent pas contre un déni de service réseau ni contre l'épuisement d'autres ressources.
5. Trivy détecte après coup (analyse statique). Empêcher l'admission demande un contrôleur d'admission (Pod Security Admission, Kyverno, OPA Gatekeeper) qui refuse la ressource à la création.

## Partie G : Workflow et quality gate
- Run #1 : échec à l'étape Scan image (65 vulnérabilités). Le gate a bloqué une image obsolète
- Run #2 : succès après correction du Dockerfile. Runs #3 et #4 sur `main` : succès, avec le seuil MEDIUM actif sur les manifests
- Test de la section 9.1 : PR #1 (branche `test-gate`) avec `runAsNonRoot: false` uniquement. Le job échoue à l'étape Scan Kubernetes manifests : 1 alerte `KSV-0012` (MEDIUM), 39 contrôles sur 40 réussis. Les étapes Build image, Scan image et Helm lint passent. La PR n'a pas été fusionnée et la branche a été supprimée.

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

## Preuves

Captures réalisées pendant le TP : terminal de la VM et interface GitHub. Les fichiers sont dans `docs/screenshots/`. Les captures sont classées dans l'ordre des parties du rapport.

### Environnement et préparation

**Versions des outils (git, Docker, kubectl, Helm, Trivy, kind) et contexte kubectl `default` (cluster k3s).**

![01-env-outils-versions](docs/screenshots/01-env-outils-versions.png)

**Noeud k3s `Ready`, initialisation du dépôt, structure des dossiers et création de `index.html`.**

![02-env-depot-index-html](docs/screenshots/02-env-depot-index-html.png)

### Partie A : Workflow CI et épinglage des actions

**Workflow `secure-ci.yml` : `permissions: contents: read`, `persist-credentials: false`, `timeout-minutes`, marqueurs de SHA encore à remplacer.**

![03-a-workflow-avant-epinglage](docs/screenshots/03-a-workflow-avant-epinglage.png)

**Récupération des tags et des SHA des actions avec `git ls-remote --tags` (le SHA du commit est sur la ligne `^{}`).**

![04-a-recuperation-sha-actions](docs/screenshots/04-a-recuperation-sha-actions.png)

**Remplacement des marqueurs par les SHA complets, liste des alertes ajoutées par la configuration affaiblie (`KSV-0001`, `KSV-0012`) et passage du seuil du scan de manifests à `CRITICAL,HIGH,MEDIUM`.**

![05-a-remplacement-sha-seuil-medium](docs/screenshots/05-a-remplacement-sha-seuil-medium.png)

**Contrôle final : 4 actions épinglées par SHA de 40 caractères avec leur version en commentaire, aucun marqueur restant, seuils `CRITICAL,HIGH` (image) et `CRITICAL,HIGH,MEDIUM` (manifests).**

![06-a-verification-uses-severity](docs/screenshots/06-a-verification-uses-severity.png)

### Partie B : Image et Trivy

**Premier build de l'image (base `nginx-unprivileged:1.27-alpine`).**

![07-b-build-image-initial](docs/screenshots/07-b-build-image-initial.png)

**Scan Trivy de l'image initiale (Alpine 3.21.3) : 65 vulnérabilités HIGH/CRITICAL avec correctif (62 HIGH, 3 CRITICAL).**

![08-b-trivy-image-65-vulnerabilites](docs/screenshots/08-b-trivy-image-65-vulnerabilites.png)

**Test d'une base plus récente (`stable-alpine`, Alpine 3.24.2) : modification du Dockerfile et rebuild.**

![09-b-base-stable-alpine](docs/screenshots/09-b-base-stable-alpine.png)

**Scan de l'image sur Alpine 3.24.2 : il reste 10 vulnérabilités (9 HIGH, 1 CRITICAL).**

![10-b-trivy-image-10-vulnerabilites](docs/screenshots/10-b-trivy-image-10-vulnerabilites.png)

**Dockerfile final avec `apk upgrade --no-cache` (retour à `USER 101`), import dans k3s et redémarrage du déploiement.**

![11-b-dockerfile-final-apk-upgrade](docs/screenshots/11-b-dockerfile-final-apk-upgrade.png)

**Rebuild sans cache et nouveau scan : 0 vulnérabilité HIGH/CRITICAL.**

![12-b-trivy-image-0-vulnerabilite](docs/screenshots/12-b-trivy-image-0-vulnerabilite.png)

**Incident : le scan local échoue (`context deadline exceeded` sur le socket Docker) pendant le téléchargement de la base Trivy. Contournement : `docker save` puis `trivy image --input`.**

![13-b-incident-scan-local-socket-docker](docs/screenshots/13-b-incident-scan-local-socket-docker.png)

### Partie C : Chart Helm

**Création du `Dockerfile`, de `Chart.yaml`, `values.yaml` et `serviceaccount.yaml`.**

![14-c-dockerfile-chart-values](docs/screenshots/14-c-dockerfile-chart-values.png)

**`deployment.yaml` : `runAsNonRoot`, `runAsUser: 101`, seccomp `RuntimeDefault`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, capabilities `drop: [ALL]`, volume `emptyDir` sur `/tmp`, requests et limits.**

![15-c-deployment-securitycontext](docs/screenshots/15-c-deployment-securitycontext.png)

**`service.yaml` (ClusterIP) et `deployer-rbac.yaml` (ServiceAccount, Role et RoleBinding limités au namespace).**

![16-c-service-et-rbac-yaml](docs/screenshots/16-c-service-et-rbac-yaml.png)

**`trivy config` sur le rendu Helm : seules des alertes LOW subsistent (par exemple `KSV-0021` et `KSV-0110`).**

![17-c-trivy-config-alertes-low](docs/screenshots/17-c-trivy-config-alertes-low.png)

### Partie D : Déploiement

**Import de l'image dans containerd (`docker save | sudo k3s ctr images import -`), équivalent de `kind load docker-image` sur k3s.**

![18-d-import-image-k3s](docs/screenshots/18-d-import-image-k3s.png)

**`helm uninstall` puis `helm upgrade --install` : release `deployed`, 2 Pods `1/1 Running`, Service ClusterIP.**

![19-d-helm-install-pods-running](docs/screenshots/19-d-helm-install-pods-running.png)

**Rebuild de l'image corrigée, import, `rollout restart` réussi et `id` dans le Pod : `uid=101(nginx)`.**

![20-d-rebuild-rollout-uid101](docs/screenshots/20-d-rebuild-rollout-uid101.png)

**2 Pods `Running` avec l'image corrigée, `kubectl port-forward` puis `curl -I` : `HTTP/1.1 200 OK`.**

![21-d-pods-running-curl-200](docs/screenshots/21-d-pods-running-curl-200.png)

### Partie E : RBAC

**Création du ServiceAccount, du Role et du RoleBinding, puis vérifications `kubectl auth can-i --as=...` : `yes` pour get et create deployments (tp-deployer), `no` pour tout le reste.**

![22-e-rbac-can-i](docs/screenshots/22-e-rbac-can-i.png)

### Partie F : Durcissement du Pod

**Inspection du Pod déployé (`kubectl get pod -o yaml`, `describe`, `exec ... id`) : `automountServiceAccountToken: false`, probes, image `tp6-web:local`.**

![23-f-pod-yaml-securitycontext](docs/screenshots/23-f-pod-yaml-securitycontext.png)

**Requests et limits du conteneur, puis `trivy config` de la version sécurisée : 102 tests, 3 échecs LOW.**

![24-f-ressources-trivy-config-securise](docs/screenshots/24-f-ressources-trivy-config-securise.png)

**Version affaiblie (copie locale, jamais appliquée au cluster) avec `runAsNonRoot: false` et `allowPrivilegeEscalation: true` : 5 échecs dont 2 MEDIUM.**

![25-f-config-affaiblie-trivy](docs/screenshots/25-f-config-affaiblie-trivy.png)

**Comparaison des deux scans : 102 tests et 3 échecs (sécurisée) contre 104 tests et 5 échecs (affaiblie).**

![26-f-comparaison-securise-affaibli](docs/screenshots/26-f-comparaison-securise-affaibli.png)

**Identifiants des alertes ajoutées par la configuration affaiblie (`KSV-0001`, `KSV-0012`), puis création de la branche de test `test-gate`.**

![27-f-diff-ksv-branche-test](docs/screenshots/27-f-diff-ksv-branche-test.png)

### Partie G : Workflow et quality gate

**Run #1 sur GitHub Actions : l'étape Scan image échoue (le quality gate bloque l'image obsolète).**

![28-g-run1-rouge-scan-image](docs/screenshots/28-g-run1-rouge-scan-image.png)

**Liste des runs : run #1 en échec, runs #2 et #3 réussis.**

![29-g-liste-runs-rouge-vert](docs/screenshots/29-g-liste-runs-rouge-vert.png)

**Run #2 après correction du Dockerfile : toutes les étapes sont réussies.**

![30-g-run2-vert](docs/screenshots/30-g-run2-vert.png)

**Commit et push du correctif du Dockerfile (contrôle gitleaks : aucune fuite).**

![31-g-commit-push-correctif](docs/screenshots/31-g-commit-push-correctif.png)

**Pull request de test (`runAsNonRoot: false`) : « All checks have failed », 1 contrôle en échec.**

![32-g-pr-checks-failed](docs/screenshots/32-g-pr-checks-failed.png)

**Liste des runs avec le run de la pull request en échec, au-dessus des runs réussis sur `main`.**

![33-g-liste-runs-avec-pr-rouge](docs/screenshots/33-g-liste-runs-avec-pr-rouge.png)

**Run de la PR : Build image, Scan image et Helm lint passent, l'étape Scan Kubernetes manifests échoue.**

![34-g-pr-etape-scan-manifests-rouge](docs/screenshots/34-g-pr-etape-scan-manifests-rouge.png)

**Log de l'étape en échec : 40 tests, 1 échec MEDIUM, `KSV-0012` (`runAsNonRoot` doit être à true), `Process completed with exit code 1`.**

![35-g-pr-log-ksv-0012](docs/screenshots/35-g-pr-log-ksv-0012.png)

**Suppression de la branche de test et contrôle que `runAsNonRoot: true` est bien conservé sur `main`.**

![36-g-nettoyage-branche-test](docs/screenshots/36-g-nettoyage-branche-test.png)
