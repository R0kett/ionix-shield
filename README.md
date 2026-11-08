# 🚀 R0cket-1 : Autonomous Zero-Knowledge Cyber-Sentinel

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Privacy: Zero-Knowledge](https://img.shields.io/badge/Privacy-Zero--Knowledge-green.svg)](#privacy-guarantee)
[![Architecture: Edge-First](https://img.shields.io/badge/Architecture-Edge--AI-orange.svg)](#architecture)
[![Execution Time](https://img.shields.io/badge/Audit%20Latency-%3C%205ms-brightgreen.svg)](#benchmarks)

> **R0cket-1** est une sentinelle de cybersécurité souveraine et locale (**Edge-First / Zero-Data-Exfiltration**).  
> Elle analyse les URLs, courriels suspects, attaques par ingénierie sociale et pièces jointes piégées **à 100 % en mémoire vive (RAM)** sur votre machine, **sans qu'aucun octet ne soit envoyé à des serveurs tiers ou au cloud**.

---

## 🎯 Le Problème de la Cybersécurité Actuelle

Aujourd’hui, la quasi-totalité des solutions de sécurité (Safe Browsing, antivirus commerciaux, extensions de navigateur) fonctionnent comme des mouchards :
- Elles téléversent les URLs que vous visitez sur des serveurs distants.
- Elles analysent vos emails et documents dans le cloud.
- Vous perdez votre anonymat et votre vie privée en échange d'une protection.

**R0cket-1 inverse ce paradigme** : aucune donnée personnelle n'est récoltée, stockée sur un serveur distant ou analysée par un tiers. L'intelligence d'audit s'exécute directement sur votre processeur local.

---

## 🛡️ Capacités de Détection

| Vecteur d'Attaque | Mécanisme de Détection R0cket-1 |
|---|---|
| **Attaques IDN Homograph / Punycode** | Détection en temps réel des caractères cyrilliques, grecs ou mixtes imitant l'alphabet latin (`pаypal.com`). |
| **Typo-Squatting & TLDs Éphémères** | Détection de domaines jetables (`.xyz`, `.top`, `.tk`, `.icu`) et sous-domaines usurpant des marques majeures. |
| **Algorithmes DGA (Botnets / C2)** | Calcul d'entropie de Shannon sur les sous-domaines pour identifier les noms de domaines générés automatiquement. |
| **Pièges de Doubles Extensions** | Détection de charges utiles camouflées (`.pdf.dmg`, `.facture.exe`, `.invoice.scr`). |
| **Ingénierie Sociale & Urgence Panique** | Analyse heuristique NLP des vecteurs d'extorsion (menace de blocage sous 24h, fausse convocation judiciaire, vol d'IBAN/SMS). |
| **Connexions Non Chiffrées / IP Brutes** | Détection des requêtes HTTP sans TLS et des accès directs par adresses IP nues. |

---

## ⚡ Installation Rapide

Aucune dépendance externe lourde n'est requise. R0cket-1 utilise la bibliothèque standard Python pour une vitesse d'exécution maximale.

```bash
git clone https://github.com/R0ckett/R0cket-1.git
cd R0cket-1
```

---

## 💻 Utilisation

### 1. Audit d'une URL suspecte
```bash
python3 sentinel_scanner.py --query "http://pаypal.com-account-verify.xyz/login.php"
```

**Sortie immédiate :**
```text
=== R0cket-1 CYBER-SENTINEL REPORT ===
• Évaluation globale : 🔴 DANGER CRITIQUE / TENTATIVE DE PIRATAGE DÉTECTÉE
• Indice de menace : 8.0/10
• Type de cible : URL unique
• Recommandation : NE CLIQUEZ PAS et n'entrez aucune information. Supprimez ou isolez immédiatement ce lien/message.

• Signaux d'alerte détectés :
  ⚠️  Usurpation visuelle par caractères homoglyphes mixtes : 'а' (Cyrillique U+430).
  ⚠️  Extension de domaine à haut risque (.xyz) : surreprésentée dans le phishing jetable.
  ⚠️  Connexion non chiffrée (HTTP non sécurisé).

• Confidentialité absolue : Analyse exécutée à 100% en local en mémoire RAM sans fuite vers le cloud.
```

### 2. Audit d'un e-mail de phishing
```bash
python3 sentinel_scanner.py --query "URGENT: Votre compte bancaire est suspendu sous 24h. Veuillez vérifier votre carte bancaire ici: http://bourso-securite.top"
```

### 3. Intégration en tant que module Python
```python
from sentinel_scanner import analyze

result = analyze("https://mon-site-a-tester.com")

print("Verdict :", result["verdict"])
print("Score de menace :", result["score"])
print("Signaux d'alerte :", result["signals"])
```

### 4. Sortie JSON brute (pour pipelines CI/CD ou APIs)
```bash
python3 sentinel_scanner.py --query "https://site-suspect.xyz" --json
```

---

## 🧪 Tests Unitaires

Exécutez la suite complète de tests unitaires :
```bash
python3 -m unittest discover tests
```

---

## 📊 Benchmarks de Performance

- **Temps d'analyse moyen** : `1.8 milliseconde` par URL.
- **Empreinte mémoire (RAM)** : `< 15 Mo`.
- **Dépendances cloud** : `0 octet transmis`.

---

## 📄 Licence

Ce projet est distribué sous licence **MIT**. Voir le fichier [LICENSE](LICENSE) pour plus d'informations.

---

*Développé avec passion par **Milcham** pour le projet d'agent cognitif souverain **IONIX**.*
