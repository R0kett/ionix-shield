#!/usr/bin/env python3
"""
R0cket-1: Autonomous Zero-Knowledge Edge AI Cyber-Sentinel
=========================================================
An ultra-fast, privacy-first cybersecurity scanner that runs 100% locally in RAM.
Inspects URLs, emails, messages, and attachments with ZERO data exfiltration.

Author: Milcham (IONIX Project)
License: MIT
"""

import argparse
import json
import math
import re
import sys
import unicodedata
from urllib.parse import urlparse

__version__ = "1.0.0"

# Statistically overrepresented TLDs in disposable phishing and payload drops
HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "icu", "buzz", "fit", "rest",
    "country", "loan", "work", "click", "link", "monster", "bar", "surf",
    "club", "kim", "vip", "men", "bid", "stream", "download", "racing"
}

# High-profile brands frequently targeted by impersonation campaigns
TARGETED_BRANDS = {
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "meta", "ameli", "impots", "antai", "banque", "credit-agricole", "bnp",
    "societe-generale", "bourso", "boursorama", "labanquepostale", "orange",
    "free", "sfr", "chronopost", "colissimo", "ups", "dhl", "whatsapp", "telegram"
}

# Psychological social engineering vectors (urgency, legal coercion, credential harvesting)
SOCIAL_ENGINEERING_CUES = [
    (r"(?:bloqu[eé]|suspendu|clôtur[eé]|ferm[eé])\s*(?:sous|dans|d'ici)\s*(?:24|48|quelques)?\s*(?:h|heures|jours)", 3.0, "Menace de blocage imminent sous contrainte de temps (Urgency trap)"),
    (r"(?:action\s+requise|urgent|immédiat|d[eé]marche\s+obligatoire)", 1.5, "Injonction d'urgence artificielle"),
    (r"(?:infraction|amende|antai|huissier|pv\s+impay[eé]|gendarmerie|police|proc[eè]s)", 3.0, "Usurpation d'autorité judiciaire ou contraventionnelle"),
    (r"(?:remboursement|indemnit[eé]|cr[eé]dit|gain|virement\s+en\s+attente)", 2.0, "Appât financier trompeur (faux remboursement ou gain)"),
    (r"(?:mot\s*de\s*passe|code\s*sms|coordonn[eé]es\s*bancaires|carte\s*bancaire|iban|identifiant)", 2.5, "Tentative de captation d'identifiants sensibles"),
    (r"(?:mise\s*[aà]\s*jour\s*de\s*sécurit[eé]|vérifi(?:ez|cation)\s*de\s*votre\s*compte)", 2.0, "Faux prétexte d'audit ou de vérification de sécurité")
]

# High-risk executable or script extensions
DANGEROUS_EXTENSIONS = {
    "apk": ("Application Android non vérifiée", 4.0),
    "dmg": ("Installateur macOS externe", 2.5),
    "pkg": ("Paquet d'installation système macOS", 3.0),
    "exe": ("Exécutable Windows", 3.5),
    "scr": ("Script économiseur d'écran (vecteur trojan classique)", 4.0),
    "vbs": ("Script VBScript malveillant", 4.0),
    "bat": ("Fichier batch script", 3.5),
    "sh": ("Script Shell non audité", 2.0),
    "dylib": ("Bibliothèque dynamique injectable", 4.0),
    "iso": ("Image disque virtuelle (évitement d'antivirus)", 3.5),
}


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect Domain Generation Algorithms (DGA)."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def detect_homoglyphs(text: str) -> list:
    """Detects Cyrillic, Greek or mixed-script lookalikes imitating Latin characters."""
    findings = []
    has_latin = False
    has_cyrillic = False
    has_greek = False

    for char in text:
        cat = unicodedata.category(char)
        if not cat.startswith("L"):
            continue
        name = unicodedata.name(char, "")
        if "LATIN" in name:
            has_latin = True
        elif "CYRILLIC" in name:
            has_cyrillic = True
            findings.append((char, "Cyrillique U+" + hex(ord(char))[2:].upper(), name))
        elif "GREEK" in name:
            has_greek = True
            findings.append((char, "Grec U+" + hex(ord(char))[2:].upper(), name))

    is_mixed = has_latin and (has_cyrillic or has_greek)
    return findings if is_mixed else []


def extract_urls(text: str) -> list:
    """Extracts explicit URLs from raw text."""
    return re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", text)


def audit_url(raw_url: str) -> dict:
    """Performs deep heuristic security auditing on a single URL."""
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        url = "http://" + raw_url
    else:
        url = raw_url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()

    score = 0.0
    threat_signals = []

    # 1. IDN Homoglyph / Punycode Attacks
    if "xn--" in hostname:
        score += 4.5
        threat_signals.append("Attaque Punycode IDN détectée : le domaine camoufle des caractères non-latins.")

    homos = detect_homoglyphs(hostname)
    if homos:
        score += 5.0
        details = ", ".join(f"'{c}' ({desc})" for c, desc, _ in homos[:3])
        threat_signals.append(f"Usurpation visuelle par caractères homoglyphes mixtes : {details}.")

    # 2. High-Risk TLDs
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in HIGH_RISK_TLDS:
        score += 2.0
        threat_signals.append(f"Extension de domaine à haut risque (.{tld}) : surreprésentée dans le phishing jetable.")

    # 3. Brand Impersonation & Typo-squatting
    for brand in TARGETED_BRANDS:
        if brand in hostname:
            parts = hostname.split(".")
            root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
            if brand not in root_domain:
                score += 4.5
                threat_signals.append(f"Usurpation flagrante de marque : '{brand}' est injecté dans un sous-domaine de '{root_domain}'.")
            elif any(f"{brand}-" in part or f"-{brand}" in part for part in parts):
                score += 3.5
                threat_signals.append(f"Typo-squatting probable : nom de domaine combiné suspect exploitant la marque '{brand}'.")

    # 4. DGA Entropy Calculation
    subdomains = hostname.split(".")[:-2]
    for sub in subdomains:
        if len(sub) >= 9:
            ent = calculate_entropy(sub)
            if ent >= 3.6:
                score += 2.5
                threat_signals.append(f"Sous-domaine à forte entropie ({ent}) : structure générée par algorithme DGA (C2 botnet).")

    # 5. Hidden Payload & Disguised Double Extensions
    for ext, (label, ext_score) in DANGEROUS_EXTENSIONS.items():
        if path.endswith(f".{ext}"):
            score += ext_score
            threat_signals.append(f"Téléchargement direct d'exécutable/installateur ({ext.upper()}) : {label}.")
        double_ext_match = re.search(r"\.(pdf|docx?|xlsx?|jpg|png|zip)\.(" + ext + r")$", path)
        if double_ext_match:
            score += 5.0
            threat_signals.append(f"Piège de double extension masquée ({double_ext_match.group(0)}) : exécutable camouflé en document anodin.")

    # 6. Raw IP Navigation & Unencrypted HTTP
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        score += 3.0
        threat_signals.append("Navigation par adresse IP brute directe : contournement des réputations DNS.")
    elif url.startswith("http://") and score > 0:
        score += 1.0
        threat_signals.append("Connexion non chiffrée (HTTP non sécurisé).")

    return {
        "url": raw_url,
        "hostname": hostname,
        "score": round(score, 1),
        "threat_signals": threat_signals
    }


def audit_text(text: str) -> dict:
    """Performs full inspection on unstructured message/email content."""
    score = 0.0
    cues_found = []

    for pattern, weight, description in SOCIAL_ENGINEERING_CUES:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            score += weight
            cues_found.append(description)

    urls = extract_urls(text)
    url_audits = [audit_url(u) for u in urls]

    max_url_score = max((u["score"] for u in url_audits), default=0.0)
    total_score = round(score + max_url_score, 1)

    return {
        "text_length": len(text),
        "urls_detected": len(urls),
        "url_audits": url_audits,
        "social_engineering_score": round(score, 1),
        "social_engineering_cues": cues_found,
        "composite_score": total_score
    }


def analyze(target: str) -> dict:
    """Unified entrypoint for auditing any target (URL or message)."""
    urls = extract_urls(target)
    is_pure_url = len(urls) == 1 and len(target.strip().split()) == 1

    if is_pure_url:
        audit = audit_url(urls[0])
        score = audit["score"]
        signals = audit["threat_signals"]
        target_type = "url"
    else:
        email_res = audit_text(target)
        score = email_res["composite_score"]
        signals = email_res["social_engineering_cues"]
        for ua in email_res["url_audits"]:
            signals.extend(ua["threat_signals"])
        target_type = "message_or_email"

    if score >= 4.5:
        verdict = "DANGER_CRITIQUE"
        verdict_label = "🔴 DANGER CRITIQUE / TENTATIVE DE PIRATAGE DÉTECTÉE"
        recommendation = "NE CLIQUEZ PAS et n'entrez aucune information. Supprimez ou isolez immédiatement ce lien/message."
    elif score >= 2.0:
        verdict = "SUSPECT"
        verdict_label = "🟡 VIGILANCE ÉLEVÉE / ANOMALIES SUSPECTES"
        recommendation = "Méfiance requise : plusieurs indicateurs inhabituels sont présents. Ne fournissez aucun identifiant."
    else:
        verdict = "SAIN"
        verdict_label = "🟢 APPAREMMENT SÛR / AUCUNE MENACE ÉVIDENTE DÉTECTÉE"
        recommendation = "Aucun marqueur malveillant classique n'a été relevé. Maintenez vos réflexes d'hygiène habituels."

    summary_lines = [
        "=== R0cket-1 CYBER-SENTINEL REPORT ===",
        f"• Évaluation globale : {verdict_label}",
        f"• Indice de menace : {score}/10",
        f"• Type de cible : {'URL unique' if target_type == 'url' else 'Message / Courriel'}",
        f"• Recommandation : {recommendation}\n"
    ]

    if signals:
        summary_lines.append("• Signaux d'alerte détectés :")
        for s in signals:
            summary_lines.append(f"  ⚠️  {s}")
    else:
        summary_lines.append("• Analyse locale : Syntaxe saine, zéro homoglyphe, structure standard.")

    summary_lines.append("\n• Confidentialité absolue : Analyse exécutée à 100% en local en mémoire RAM sans fuite vers le cloud.")

    return {
        "status": "success",
        "verdict": verdict,
        "score": score,
        "target_type": target_type,
        "signals": signals,
        "raw_summary": "\n".join(summary_lines)
    }


def main():
    parser = argparse.ArgumentParser(description="R0cket-1 Cyber-Sentinel: Edge-First Security Analyzer")
    parser.add_argument("--query", "-q", default="", help="URL, email body, or message text to inspect")
    parser.add_argument("--json", action="store_true", help="Output raw JSON only")
    args = parser.parse_args()

    content = args.query.strip()
    if not content:
        if not sys.stdin.isatty():
            content = sys.stdin.read().strip()

    if not content:
        print("Usage: python3 sentinel_scanner.py --query '<URL or message>'")
        sys.exit(1)

    result = analyze(content)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(result["raw_summary"])


if __name__ == "__main__":
    main()
