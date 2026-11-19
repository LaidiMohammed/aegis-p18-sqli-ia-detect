# AEGIS — P18 — Détection SQLi (IA light)

[![Vercel](https://img.shields.io/badge/Vercel-aegis-p18--blue?logo=vercel)](https://aegis-p18-sqli-ia-detect.vercel.app)
[![Tests](https://img.shields.io/badge/Tests-passing-brightgreen)]

Détection SQLi (IA light) — PFE P13 style AEGIS (Master 1 Sécurité informatique).

## Infos rapides

| Élément | Valeur |
|---|---|
| **GitHub** | https://github.com/LaidiMohammed/aegis-p18-sqli-ia-detect |
| **Vercel** | https://aegis-p18-sqli-ia-detect.vercel.app |
| **Stacks** | DVWA, sqlmap, scikit-learn/TensorFlow |
| **Type** | fg |
| **Ethique** | Labo local, anti-GPU, anti-cloud, stand-alone |

## Install

```bash
pip install -r requirements.txt
make install  # (venv)
```

## Smoke & tests (démo à la prof)

```bash
make smoke   # ou: scripts/run_smoke.sh
make test
```

## Fonctions à exécuter à la démo

Voir [`docs/ETHICS.md`](docs/ETHICS.md), [`docs/SPEC.md`](docs/SPEC.md).
