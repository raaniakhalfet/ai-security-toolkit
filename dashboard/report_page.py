"""Builds the printable test report (HTML, A4). Open /report in the Control Center, then Print > Save as PDF."""
import html
from datetime import datetime
from math import sqrt


def wilson(s, n, z=1.96):
    if not n:
        return 0.0, 1.0
    p = s / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def pct(s, n):
    return round(100 * s / n) if n else 0


def ci(s, n):
    lo, hi = wilson(s, n)
    return f"{round(100 * lo)}-{round(100 * hi)}%"


TXT = {
    "en": {
        "title": "AI Security Toolkit: test report", "sub": "Local lab, fake data only. Generated {date}.",
        "h_sum": "Summary", "h_res": "Results by attack set", "h_find": "Findings", "h_cov": "What the attacks cover",
        "h_aud": "Permission audit", "h_fa": "False alarms", "h_rec": "Recommendations", "h_lim": "Limits of this test",
        "h_live": "Live testing and monitoring",
        "setup": "Setup", "worked": "Attacks that worked", "partial": "Worked or partly", "runs": "runs", "interval": "95% interval",
        "sum1": "Without any defence, {a}% of attack runs caused real harm ({as_}/{an}, 95% interval {aci}). With the firewall and the in-agent guard together, {b}% did ({bs}/{bn}, 95% interval {bci}).",
        "sum2": "Real harm means a secret shown to the user or an email sent. Attack sets: {sets}.",
        "sum3": "Normal customer questions wrongly blocked: {fa} of {fn} (95% interval {fci}).",
        "f_fw": "{set}: the firewall alone let {s} of {n} runs through ({p}%, interval {c}). One layer is not enough.",
        "f_gd": "{set}: the guard alone let {s} of {n} runs through ({p}%, interval {c}).",
        "f_both": "Firewall + guard: {s} harmful runs out of {n} across all sets (interval {c}).",
        "f_root": "Secret removed from the prompt + guard: {s} harmful runs out of {n} across all sets (interval {c}).",
        "f_chal": "Challenge mode: {n} attempts, {u} worked without protection, {g} got through the protection.",
        "f_can": "Canary tokens: {n} critical alert(s) recorded.",
        "cat": "Attack type", "owasp": "OWASP LLM Top 10", "atlas": "MITRE ATLAS", "atk": "Attacks", "nod": "Without defence", "bth": "Firewall + guard",
        "notcov": "Not covered yet: {x}.", "atlasnote": "ATLAS IDs AML.T0051 and AML.T0086 were checked on MITRE pages; the others come from secondary sources and must be checked on atlas.mitre.org.",
        "tool": "Tool", "risk": "Inherent risk", "dn": "Dangerous calls allowed (normal)", "dh": "(hardened)", "verdict": "Verdict", "noaud": "No audit yet. Run python audit.py in the audit folder.",
        "fa_txt": "{fn} normal customer questions were sent through the input filter ({tune} used to tune the rules, {unseen} written afterwards and never used to tune). Wrongly blocked: {fa}. Two questions that mention a personal gmail address are blocked on purpose by the email policy.",
        "rec": ["Never put a secret in a system prompt. Removing it gave 0 harmful runs when combined with the guard.",
                "Keep both layers: the firewall reads messages and replies, the guard limits what tools may do. Each leaves gaps alone.",
                "Require a human approval for risky actions such as sending email (REQUIRE_APPROVAL=1).",
                "Plant canary tokens: any use of a fake secret is a certain sign of theft.",
                "Keep testing on attacks that were never used to tune the rules, and have a teammate write the next set.",
                "Send the alert file to a SIEM (Wazuh rules are provided) and test them live."],
        "lim": ["Small local model (llama3.2:3b) and 5 runs per attack: a rough guide, hence the intervals. 0% means below roughly 4 to 6%, not zero.",
                "The firewall is rule-based; a differently worded attack can pass. The guard and the output filter are what stop it.",
                "Unseen set 2 was written after the firewall rules were fixed by the same author.",
                "Multi-turn attacks, training-data poisoning, model theft and supply-chain attacks are not covered.",
                "Wazuh rules are written but not tested on a live server."],
        "print": "Save as PDF (Print)", "none_run": "not run",
    },
    "fr": {
        "title": "AI Security Toolkit : rapport de test", "sub": "Laboratoire local, fausses données uniquement. Généré le {date}.",
        "h_sum": "Résumé", "h_res": "Résultats par jeu d’attaques", "h_find": "Constats", "h_cov": "Ce que couvrent les attaques",
        "h_aud": "Audit des permissions", "h_fa": "Fausses alarmes", "h_rec": "Recommandations", "h_lim": "Limites de ce test",
        "h_live": "Tests en direct et surveillance",
        "setup": "Configuration", "worked": "Attaques réussies", "partial": "Réussies ou partielles", "runs": "essais", "interval": "intervalle à 95 %",
        "sum1": "Sans aucune défense, {a} % des essais d’attaque ont fait un vrai dégât ({as_}/{an}, intervalle à 95 % {aci}). Avec le pare-feu et la garde ensemble, {b} % ({bs}/{bn}, intervalle à 95 % {bci}).",
        "sum2": "Un vrai dégât veut dire un secret montré à l’utilisateur ou un e-mail envoyé. Jeux d’attaques : {sets}.",
        "sum3": "Questions normales de clients bloquées à tort : {fa} sur {fn} (intervalle à 95 % {fci}).",
        "f_fw": "{set} : le pare-feu seul a laissé passer {s} essais sur {n} ({p} %, intervalle {c}). Une seule barrière ne suffit pas.",
        "f_gd": "{set} : la garde seule a laissé passer {s} essais sur {n} ({p} %, intervalle {c}).",
        "f_both": "Pare-feu + garde : {s} essais nuisibles sur {n}, tous jeux confondus (intervalle {c}).",
        "f_root": "Secret retiré du prompt + garde : {s} essais nuisibles sur {n}, tous jeux confondus (intervalle {c}).",
        "f_chal": "Mode défi : {n} tentatives, {u} ont marché sans protection, {g} ont traversé la protection.",
        "f_can": "Pièges à secret : {n} alerte(s) critique(s) enregistrée(s).",
        "cat": "Type d’attaque", "owasp": "OWASP LLM Top 10", "atlas": "MITRE ATLAS", "atk": "Attaques", "nod": "Sans défense", "bth": "Pare-feu + garde",
        "notcov": "Pas encore couvert : {x}.", "atlasnote": "Les numéros AML.T0051 et AML.T0086 ont été vérifiés sur les pages de MITRE ; les autres viennent de sources secondaires et doivent être vérifiés sur atlas.mitre.org.",
        "tool": "Outil", "risk": "Risque de départ", "dn": "Appels dangereux permis (normal)", "dh": "(renforcé)", "verdict": "Verdict", "noaud": "Pas encore d’audit. Lance python audit.py dans le dossier audit.",
        "fa_txt": "{fn} questions normales de clients ont traversé le filtre d’entrée ({tune} ont servi à régler les règles, {unseen} écrites après et jamais utilisées pour régler). Bloquées à tort : {fa}. Deux questions avec une adresse gmail personnelle sont bloquées exprès par la politique d’e-mail.",
        "rec": ["Ne jamais mettre un secret dans le prompt système. Le retirer, avec la garde, a donné 0 essai nuisible.",
                "Garder les deux couches : le pare-feu lit messages et réponses, la garde limite les outils. Chacune laisse des trous seule.",
                "Exiger une validation humaine pour les actions risquées comme l’envoi d’e-mails (REQUIRE_APPROVAL=1).",
                "Placer des pièges à secret : toute utilisation d’un faux secret est un signe certain de vol.",
                "Continuer à tester sur des attaques jamais utilisées pour régler les règles, et faire écrire le prochain jeu par un coéquipier.",
                "Envoyer le fichier d’alertes à un SIEM (règles Wazuh fournies) et les tester en direct."],
        "lim": ["Petit modèle local (llama3.2:3b) et 5 essais par attaque : une mesure approximative, d’où les intervalles. 0 % veut dire moins de 4 à 6 %, pas zéro.",
                "Le pare-feu suit des règles : une attaque formulée autrement peut passer. La garde et le filtre de sortie l’arrêtent.",
                "Le jeu 2 a été écrit par la même personne, après la correction des règles du pare-feu.",
                "Les attaques en plusieurs tours, l’empoisonnement des données, le vol de modèle et la chaîne d’approvisionnement ne sont pas couverts.",
                "Les règles Wazuh sont écrites mais pas testées sur un serveur en direct."],
        "print": "Enregistrer en PDF (Imprimer)", "none_run": "non lancé",
    },
}

SETUP_FR = {"No defence": "Aucune défense", "Firewall only": "Pare-feu seul", "Guard only": "Garde seule",
            "Firewall + guard": "Pare-feu + garde", "Secret removed + guard": "Secret retiré + garde"}
TITLE_FR = {"Original 12 attacks": "12 attaques d’origine", "12 unseen attacks": "12 attaques jamais vues",
            "18 more unseen attacks": "18 autres attaques jamais vues"}
CAT_FR = {"prompt leak": "fuite du prompt", "jailbreak": "jailbreak", "indirect injection": "injection indirecte",
          "sensitive file access": "accès à un fichier sensible", "path traversal": "traversée de chemin", "unauthorized action": "action non autorisée"}

CSS = """
@page{size:A4;margin:16mm}
body{font-family:'Segoe UI',Arial,sans-serif;color:#14213d;line-height:1.45;max-width:820px;margin:24px auto;padding:0 18px;font-size:14px}
h1{font-size:28px;margin:0 0 4px}h2{font-size:19px;margin:26px 0 8px;border-bottom:2px solid #2457d6;padding-bottom:4px;page-break-after:avoid}
h3{font-size:15px;margin:16px 0 6px}p{margin:6px 0}.sub{color:#5b6472}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px;page-break-inside:avoid}th,td{border:1px solid #d8dce6;padding:6px 8px;text-align:left;vertical-align:top}th{background:#eef2fb}
.bar{height:8px;background:#e6e9f2;border-radius:4px;min-width:60px}.bar i{display:block;height:8px;border-radius:4px;background:#e0612a}
.good{background:#e6f1ff}.bad{background:#fde9df}.big{font-size:17px;background:#f4f6fb;border-left:5px solid #2457d6;padding:10px 14px;margin:10px 0}
ul{margin:6px 0 6px 18px;padding:0}li{margin:3px 0}.note{font-size:12px;color:#5b6472}
button{background:#2457d6;color:#fff;border:0;border-radius:8px;padding:10px 18px;font-size:15px;cursor:pointer}
@media print{.noprint{display:none}body{margin:0}}
"""


def build(lang, results, fw, audit, challenge, canary_count, benign, sets_titles):
    t = TXT.get(lang, TXT["en"])
    e = html.escape
    fr = lang == "fr"
    sname = (lambda x: SETUP_FR.get(x, x)) if fr else (lambda x: x)
    stitle = (lambda x: TITLE_FR.get(x, x)) if fr else (lambda x: x)
    cname = (lambda x: CAT_FR.get(x, x)) if fr else (lambda x: x)
    # pooled numbers
    pool = {"none": [0, 0], "both": [0, 0], "rootfix": [0, 0]}
    for st in results:
        for r in st["rows"]:
            key = {"No defence": "none", "Firewall + guard": "both", "Secret removed + guard": "rootfix"}.get(r["setup"])
            if key and r["run"]:
                pool[key][0] += r["success"]
                pool[key][1] += r["n"]
    a, b = pool["none"], pool["both"]
    out = [f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'><title>{e(t['title'])}</title><style>{CSS}</style></head><body>",
           f"<div class='noprint'><button onclick='window.print()'>{e(t['print'])}</button> "
           f"<a href='/report?lang={'fr' if lang == 'en' else 'en'}'>{'Français' if lang == 'en' else 'English'}</a></div>",
           f"<h1>{e(t['title'])}</h1><p class='sub'>{e(t['sub'].format(date=datetime.now().strftime('%Y-%m-%d %H:%M')))}</p>"]
    # summary
    out.append(f"<h2>{t['h_sum']}</h2>")
    if a[1] and b[1]:
        out.append("<p class='big'>" + e(t["sum1"].format(a=pct(*a), as_=a[0], an=a[1], aci=ci(*a), b=pct(*b), bs=b[0], bn=b[1], bci=ci(*b))) + "</p>")
    out.append("<p>" + e(t["sum2"].format(sets=", ".join(stitle(x) for x in sets_titles))) + "</p>")
    if benign:
        out.append("<p>" + e(t["sum3"].format(fa=benign["wrong"], fn=benign["n"], fci=ci(benign["wrong"], benign["n"]))) + "</p>")
    # results
    out.append(f"<h2>{t['h_res']}</h2>")
    for st in results:
        out.append(f"<h3>{e(stitle(st['title']))}</h3><table><tr><th>{t['setup']}</th><th>{t['worked']}</th><th></th><th>{t['partial']}</th></tr>")
        for r in st["rows"]:
            if not r["run"]:
                out.append(f"<tr><td>{e(sname(r['setup']))}</td><td colspan='3' class='note'>{t['none_run']}</td></tr>")
                continue
            s, n = r["success"], r["n"]
            cls = "good" if s == 0 else ""
            out.append(f"<tr class='{cls}'><td>{e(sname(r['setup']))}</td><td><b>{pct(s, n)}%</b> ({s}/{n} {t['runs']}, {t['interval']} {ci(s, n)})</td>"
                       f"<td style='width:22%'><div class='bar'><i style='width:{pct(s, n)}%'></i></div></td><td>{pct(s + r['partial'], n)}%</td></tr>")
        out.append("</table>")
    # findings
    out.append(f"<h2>{t['h_find']}</h2><ul>")
    for st in results:
        for r in st["rows"]:
            if not r["run"] or not r["success"]:
                continue
            key = {"Firewall only": "f_fw", "Guard only": "f_gd"}.get(r["setup"])
            if key:
                out.append("<li>" + e(t[key].format(set=stitle(st["title"]), s=r["success"], n=r["n"], p=pct(r["success"], r["n"]), c=ci(r["success"], r["n"]))) + "</li>")
    if b[1]:
        out.append("<li>" + e(t["f_both"].format(s=b[0], n=b[1], c=ci(*b))) + "</li>")
    if pool["rootfix"][1]:
        rr = pool["rootfix"]
        out.append("<li>" + e(t["f_root"].format(s=rr[0], n=rr[1], c=ci(*rr))) + "</li>")
    out.append("</ul>")
    # live
    rows = challenge
    out.append(f"<h2>{t['h_live']}</h2><ul>")
    out.append("<li>" + e(t["f_chal"].format(n=len(rows), u=sum(1 for r in rows if r.get("unprotected_harm")), g=sum(1 for r in rows if r.get("protected_harm")))) + "</li>")
    out.append("<li>" + e(t["f_can"].format(n=canary_count)) + "</li></ul>")
    # coverage
    out.append(f"<h2>{t['h_cov']}</h2><table><tr><th>{t['cat']}</th><th>{t['owasp']}</th><th>{t['atlas']}</th><th>{t['atk']}</th><th>{t['nod']}</th><th>{t['bth']}</th></tr>")
    for r in fw["rows"]:
        n0, nb = r["none"], r["both"]
        out.append("<tr><td>" + e(cname(r["category"].replace("_", " "))) + "</td><td>" + e(", ".join(f"{o['id']} {o['name']}" for o in r["owasp"])) + "</td><td>"
                   + e(", ".join(f"{x['id']} {x['name']}" for x in r["atlas"])) + f"</td><td>{r['attacks']}</td>"
                   f"<td>{pct(*n0) if n0[1] else '-'}%</td><td>{pct(*nb) if nb[1] else '-'}%</td></tr>")
    out.append("</table><p class='note'>" + e(t["notcov"].format(x=", ".join(fw["not_covered"]))) + " " + e(t["atlasnote"]) + "</p>")
    # audit
    out.append(f"<h2>{t['h_aud']}</h2>")
    if audit.get("missing"):
        out.append("<p class='note'>" + e(t["noaud"]) + "</p>")
    else:
        out.append(f"<table><tr><th>{t['tool']}</th><th>{t['risk']}</th><th>{t['dn']}</th><th>{t['dh']}</th><th>{t['verdict']}</th></tr>")
        for x in audit["tools"]:
            out.append(f"<tr><td>{e(str(x['tool']))}</td><td>{e(str(x['inherent_risk']))}</td><td>{x['dangerous_allowed_normal']}</td><td>{x['dangerous_allowed_hardened']}</td><td>{e(str(x['verdict']))}</td></tr>")
        out.append("</table>")
    # false alarms
    if benign:
        out.append(f"<h2>{t['h_fa']}</h2><p>" + e(t["fa_txt"].format(fn=benign["n"], tune=benign["tune"], unseen=benign["unseen"], fa=benign["wrong"])) + "</p>")
    out.append(f"<h2>{t['h_rec']}</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in t["rec"]) + "</ul>")
    out.append(f"<h2>{t['h_lim']}</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in t["lim"]) + "</ul></body></html>")
    return "".join(out)
