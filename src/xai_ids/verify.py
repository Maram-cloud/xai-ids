import re

def nombres(t):
    return {str(abs(float(m))) for m in re.findall('-?[0-9]+(?:[.][0-9]+)?', t.replace(',', '.'))}

def verifier(texte, prompt):
    inventes = nombres(texte) - nombres(prompt)
    fen = texte.split('Isolation Forest')[1][:150].lower() if 'Isolation Forest' in texte else ''
    mots = set(re.findall('[a-zéèà]+', fen))
    negation = bool(mots & {'pas', 'aucune', 'aucun', 'non', 'ne', 'n'})
    return {
        '4_parties': all(k in texte for k in ['Verdict', 'Facteurs', 'confiance', 'Action']),
        'mots_ok': len(texte.split()) <= 130,
        'chiffres_inventes': sorted(inventes),
        'contradiction_IF': 'anomalie = non' in prompt and 'anomalie' in fen and not negation,
    }

def nb_problemes(v):
    return (int(not v['4_parties']) + int(not v['mots_ok'])
            + len(v['chiffres_inventes']) + int(v['contradiction_IF']))