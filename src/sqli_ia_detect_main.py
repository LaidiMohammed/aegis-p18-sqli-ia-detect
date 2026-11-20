"""Module principal — P18 Détection SQLi (IA light) — AEGIS.

Fonctions :
  - detect_sqli(query) -> dict : détection d'injection SQL dans une requête
  - analyze_query_type(query) -> str : type de requête SQL détecté
  - assess_sqli_risk(query, detected_patterns) -> str : évaluation du risque SQLi
  - generate_remediation(detected_patterns) -> list[str] : recommandations de correction
  - main(argv) -> int : CLI

Éthique : analyse locale de requêtes fournies, pas d'exécution de requêtes réelles.
Usage éducatif : aide les développeurs à repérer les injections SQL potentielles.
"""
from __future__ import annotations

import argparse
import json
import re
from typing import Any, Dict, List, Optional

# Patterns SQLi connus (regex) - indicateurs heuristiques
SQLI_PATTERNS: List[tuple] = [
    # Commentaires SQL qui masquent l'injection
    (r"--.*", "commentaire SQL"),
    (r"/\\*.*\\*/", "commentaire sur plusieurs lignes"),
    # Unions basées
    (r"\bUNION\b.*\bSELECT\b", "injonction UNION basée"),
    (r"\bUNION ALL\b", "UNION ALL basée"),
    # Requêtes booléennes
    (r"\bOR\b.*=.*['\"]*.*['\"]*", "condition OR booléenne"),
    (r"\bAND\b.*=.*['\"]*.*['\"]*", "condition AND booléenne"),
    # Erreurs basées
    (r"\bAND\s+1\s*=\s*1\b", "erreur basée (tautologie 1=1)"),
    (r"\bAND\s+1\s*=\s*0\b", "erreur basée (contrôle 1=0)"),
    # Empilement de requêtes
    (r";\s*(DROP|DELETE|INSERT|UPDATE|SELECT)\b", "empilement de requêtes"),
    # Base64 dans les requêtes (évitement de détection)
    (r"BASE64\.ENCODE\(|FROM_BASE64\b", "encodage Base64"),
    # Patterns de variables d'entrée directe
    (r"'\s*OR\s+['\"]", "variable entrée directe OR"),
    (r"'\s*AND\s+['\"]", "variable entrée directe AND"),
    # Patterns de trusted/non-trusted
    (r"http://|https://", "URL dans la requête"),
]

COMMON_SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "LIKE", "OR", "AND"]


def detect_sqli(query: str) -> Dict[str, Any]:
    """Détecte la présence d'injection SQL dans une requête donnée."""
    found_patterns: List[Dict[str, Any]] = []
    query_lower = query.lower()
    
    for pattern, description in SQLI_PATTERNS:
        matches = re.finditer(pattern, query_lower, re.IGNORECASE)
        for match in matches:
            found_patterns.append({
                "pattern": description,
                "matched": match.group(),
                "position": match.start(),
                "length": match.end() - match.start(),
            })
    
    # Déterminer s'il y a injection SQL
    has_sqli = len(found_patterns) > 0
    
    # Évaluer le niveau de risque
    if not has_sqli:
        risk_level = "aucun"
        risk_score = 0
        remediation = "Aucune injection SQL détectée - bonnes pratiques respectées"
    elif len(found_patterns) <= 2:
        risk_level = "faible"
        risk_score = len(found_patterns) * 5
        remediation = "Revue de code recommandée - échapper les entrées utilisateur"
    elif len(found_patterns) <= 5:
        risk_level = "moyen"
        risk_score = len(found_patterns) * 10
        remediation = "Corriger immédiatement - paramètres préparés obligatoires"
    else:
        risk_level = "élevé"
        risk_score = len(found_patterns) * 15
        remediation = "Urgence - isoler l'application, revue de sécurité complète"
    
    return {
        "query": query[:100] + "..." if len(query) > 100 else query,
        "has_sqli": has_sqli,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "patterns_found": found_patterns,
        "remediation": remediation,
        "total_patterns": len(found_patterns),
    }


def analyze_query_type(query: str) -> str:
    """Détermine le type principal de requête SQL."""
    query_upper = query.upper()
    found_keywords: List[str] = []
    
    for kw in COMMON_SQL_KEYWORDS:
        if kw in query_upper:
            found_keywords.append(kw)
    
    if not found_keywords:
        return "requête inconnue"
    
    # Déterminer le type principal
    if "SELECT" in found_keywords:
        # Vérifier s'il y a aussi des modifications
        if any(kw in query_upper for kw in ["INSERT", "UPDATE", "DELETE"]):
            return "SELECT avec modification"
        return "lecture SELECT"
    elif "INSERT" in found_keywords:
        return "INSERTion"
    elif "UPDATE" in found_keywords:
        return "Mise à jour UPDATE"
    elif "DELETE" in found_keywords:
        return "Suppression DELETE"
    
    return "requête " + "+".join(found_keywords)


def assess_sqli_risk(query: str, detected_patterns: List[Dict[str, Any]]) -> str:
    """Évalue le risque global d'injection SQL."""
    if not detected_patterns:
        return "aucun"
    
    high_risk_patterns = ["empilement de requêtes", "erreur basée (tautologie 1=1)"]
    medium_risk_patterns = ["injonction UNION basée", "condition OR booléenne", "condition AND booléenne"]
    
    high_count = sum(1 for p in detected_patterns if p["pattern"] in high_risk_patterns)
    medium_count = sum(1 for p in detected_patterns if p["pattern"] in medium_risk_patterns)
    
    if high_count > 0:
        return "élevé"
    elif medium_count >= 2:
        return "moyen"
    elif medium_count == 1:
        return "faible"
    else:
        return "aucun"


def generate_remediation(detected_patterns: List[Dict[str, Any]]) -> List[str]:
    """Génère des recommandations de correction basées sur les patterns détectés."""
    recs: List[str] = []
    
    # Patterns critiques nécessitant une action immédiate
    critical_patterns = ["empilement de requêtes", "commentaire SQL masquant injection"]
    medium_patterns = ["injonction UNION basée", "condition OR booléenne", "condition AND booléenne"]
    low_patterns = ["commentaire SQL"]
    
    for p in detected_patterns:
        if p["pattern"] in critical_patterns:
            recs.append("Supprimer immédiatement les chaînes d'empilement de requêtes")
            recs.append("Mettre en place des paramètres préparés (prepared statements)")
        elif p["pattern"] in medium_patterns:
            recs.append("Utiliser des requêtes paramétrées avec des entrées validées")
            recs.append("Mettre en place une liste blanche d'entrées autorisées")
        elif p["pattern"] in low_patterns:
            recs.append("Nettoyer les commentaires dans les requêtes dynamiques")
    
    # Recommandations générales si aucun pattern critique n'est détecté
    if not any(p["pattern"] in critical_patterns for p in detected_patterns):
        recs.append("Mettre en place une politique de validation des entrées utilisateur")
        recs.append("Utiliser des ORM ou bibliothèques d'abstraction SQL")
        recs.append("Effectuer des revues de code de sécurité régulières")
    
    return recs


def main(argv: list[str] | None = None) -> int:
    import warnings
    warnings.filterwarnings("ignore")

    ap = argparse.ArgumentParser(prog="sqli_ia_detect",
                                 description="AEGIS - P18 - Détection SQLi (IA light)")
    ap.add_argument("--query", default="SELECT * FROM users WHERE id = '1'", help="Requête SQL à analyser")
    ap.add_argument("--json", action="store_true", help="Sortir en JSON")
    ap.add_argument "--save-json", default=None, help="Écrire le résultat JSON")
    ap.add_argument "--pdf", default="outputs/rapport-p18.pdf", help="Chemin du PDF")
    ap.add_argument "--list-patterns", action="store_true", help="Lister les patterns SQLi connus")
    args = ap.parse_args(argv)

    try:
        if args.list_patterns:
            out = {
                "project": "P18",
                "known_patterns": len(SQLI_PATTERNS),
                "patterns": [p[1] for p in SQLI_PATTERNS],
            }
        else:
            out = detect_sqli(args.query)
            out["query_type"] = analyze_query_type(args.query)
            out["risk_assessment"] = assess_sqli_risk(args.query, out.get("patterns_found", []))
            out["remediation"] = generate_remediation(out.get("patterns_found", []))
            out["project"] = "P18"
    
    except Exception as exc:  # noqa: BLE001
        print(f"[ERREUR] {exc}")
        return 1

    if args.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        if args.list_patterns:
            print(f"[SUMMARY] P18 - Patterns SQLi connus")
            print(f"  Nombre de patterns: {out.get('known_patterns', 0)}")
            for i, name in enumerate(out.get("patterns", []), 1):
                print(f"  {i}. {name}")
        else:
            q = out.get("query", "N/A")
            has_sqli = out.get("has_sqli", False)
            risk = out.get("risk_level", "N/A")
            print(f"[SUMMARY] P18 - Détection SQLi")
            print(f"  Requête analysée: {q[:80]}...")
            print(f"  Injection détectée: {has_sqli}")
            print(f"  Niveau de risque: {risk}")
            if out.get("patterns_found"):
                print(f"  Patterns détectés: {len(out['patterns_found'])}")
                for p in out["patterns_found"][:3]:
                    print(f"    - {p['pattern']}: {p['matched'][:60]}")
            if out.get("remediation"):
                print(f"  Recommandation: {out['remediation'][0]}")

    if args.save_json:
        p = Path(args.save_json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[OK] écriture : {p}")

    if args.save_json and args.pdf:
        from src.generate_report import main as gen_main
        rc = gen_main(["--json", args.save_json, "--pdf", args.pdf])
        if rc != 0:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())