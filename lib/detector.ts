const PATTERNS: [RegExp, string][] = [
  [/--.*/i, "commentaire SQL"],
  [/\/\*.*\*\//i, "commentaire sur plusieurs lignes"],
  [/\bUNION\b.*\bSELECT\b/i, "injonction UNION basée"],
  [/\bUNION ALL\b/i, "UNION ALL basée"],
  [/\bOR\b.*=.*['"].*['"]/i, "condition OR booléenne"],
  [/\bAND\b.*=.*['"].*['"]/i, "condition AND booléenne"],
  [/\bAND\s+1\s*=\s*1\b/i, "erreur basée (tautologie 1=1)"],
  [/\bAND\s+1\s*=\s*0\b/i, "erreur basée (contrôle 1=0)"],
  [/;\s*(DROP|DELETE|INSERT|UPDATE|SELECT)\b/i, "empilement de requêtes"],
  [/BASE64\.ENCODE\(|FROM_BASE64\b/i, "encodage Base64"],
  [/'\s*OR\s+['"]/i, "variable entrée directe OR"],
  [/'\s*AND\s+['"]/i, "variable entrée directe AND"],
  [/https?:\/\//i, "URL dans la requête"],
];
const KEYWORDS = ["SELECT","INSERT","UPDATE","DELETE","FROM","WHERE","LIKE","OR","AND"];
export function detectSqli(query: string) {
  const found: Array<{ pattern: string; match: string; position: number; length: number }> = [];
  const qLower = query.toLowerCase();
  for (const [re, desc] of PATTERNS) {
    let m: RegExpExecArray | null;
    re.lastIndex = 0;
    while ((m = re.exec(qLower)) !== null) found.push({ pattern: desc, match: m[0].slice(0, 80), position: m.index, length: m[0].length });
  }
  const has = found.length > 0;
  let riskLevel: "aucun"|"faible"|"moyen"|"élevé" = "aucun";
  let riskScore = 0;
  let rem = "Aucune injection SQL détectée - bonnes pratiques respectées";
  if (!has) { riskLevel = "aucun"; riskScore = 0; }
  else if (found.length <= 2) { riskLevel = "faible"; riskScore = found.length * 5; rem = "Revue de code recommandée - échapper les entrées utilisateur"; }
  else if (found.length <= 5) { riskLevel = "moyen"; riskScore = found.length * 10; rem = "Corriger immédiatement - paramètres préparés obligatoires"; }
  else { riskLevel = "élevé"; riskScore = found.length * 15; rem = "Urgence - isoler l'application, revue de sécurité complète"; }
  return { query: query.length > 100 ? query.slice(0, 100) + "..." : query, has_sqli: has, risk_level: riskLevel, risk_score: riskScore, patterns_found: found, remediation: rem, total_patterns: found.length };
}
export function analyzeQueryType(query: string): string {
  const qu = query.toUpperCase();
  const found = KEYWORDS.filter(kw => qu.includes(kw));
  if (!found.length) return "requête inconnue";
  if (found.includes("SELECT")) { if (found.some(kw => ["INSERT","UPDATE","DELETE"].includes(kw))) return "SELECT avec modification"; return "lecture SELECT"; }
  if (found.includes("INSERT")) return "INSERTion";
  if (found.includes("UPDATE")) return "Mise à jour UPDATE";
  if (found.includes("DELETE")) return "Suppression DELETE";
  return "requête " + found.join("+");
}
export function analyzeSqli(query: string) {
  const d = detectSqli(query);
  return { project: "P18", ...d, query_type: analyzeQueryType(query), method: "Détection SQLi par regex heuristique — 0 exécution de requête réelle" };
}