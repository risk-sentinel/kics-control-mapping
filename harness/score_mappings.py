#!/usr/bin/env python3
"""Propose NIST 800-53 Rev 5 control candidates for scanner checks.

Ranks each check against a sub-part-granular control corpus using BM25 over
control statement, assessment objective and guidance text. Emits scored 1:n
candidates for human adjudication. Scores order a review queue; they are not
a mapping.

Standard library only, so a reviewer can reproduce the ranking without
installing anything.
"""
import json, math, re, sys
from collections import Counter, defaultdict

PARAM = re.compile(r'\{\{\s*insert:[^}]*\}\}')
TOKEN = re.compile(r'[a-z][a-z0-9_-]{2,}')

# Compliance prose is saturated with these; they carry no discriminating signal.
STOP = set("""the and for that with are you your this from has have not any all its it's
organization organizational organizations system systems information informational
control controls controlled defined define defines definition personnel roles
following includes include including such other others been being were was
shall must should may can will would could within into upon per each every
requirement requirements requires required policy policies procedure procedures
appropriate applicable relevant associated related additional
""".split())

# Domain synonyms: scanner vocabulary vs catalog vocabulary.
SYNONYM = {
    'logging': ['audit', 'log', 'record'], 'log': ['audit', 'record'],
    'encryption': ['cryptographic', 'encrypt', 'protection'],
    'encrypted': ['cryptographic', 'encrypt'],
    'tls': ['transmission', 'cryptographic', 'confidentiality'],
    'ssl': ['transmission', 'cryptographic', 'confidentiality'],
    'public': ['external', 'unauthorized', 'boundary'],
    'permission': ['privilege', 'authorization', 'access'],
    'permissions': ['privilege', 'authorization', 'access'],
    'iam': ['identity', 'authentication', 'account'],
    'mfa': ['multi-factor', 'authenticator', 'authentication'],
    'password': ['authenticator', 'credential'],
    'secret': ['authenticator', 'credential'],
    'backup': ['recovery', 'contingency'],
    'retention': ['retain', 'record'],
    'versioning': ['integrity', 'recovery'],
    'monitoring': ['monitor', 'surveillance', 'detection'],
    'alarm': ['alert', 'monitor', 'response'],
    'firewall': ['boundary', 'flow', 'filter'],
    'rest': ['storage', 'stored'],
    'unencrypted': ['cryptographic', 'confidentiality', 'disclosure'],
    'kms': ['cryptographic', 'key'],
    'ingress': ['boundary', 'flow', 'inbound'],
    'egress': ['boundary', 'flow', 'outbound'],
}

def tokens(text):
    text = PARAM.sub(' ', (text or '').lower())
    out = []
    for t in TOKEN.findall(text):
        if t in STOP:
            continue
        out.append(t)
        out.extend(SYNONYM.get(t, ()))
    return out

class BM25:
    def __init__(self, docs, k1=1.5, b=0.75):
        self.k1, self.b = k1, b
        self.docs = [Counter(d) for d in docs]
        self.len = [sum(d.values()) for d in self.docs]
        self.avg = (sum(self.len) / len(self.len)) if self.len else 0.0
        self.df = Counter()
        for d in self.docs:
            self.df.update(d.keys())
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in self.df.items()}
        self.post = defaultdict(list)
        for i, d in enumerate(self.docs):
            for t, f in d.items():
                self.post[t].append((i, f))

    def score(self, q):
        acc = defaultdict(float)
        for t in set(q):
            idf = self.idf.get(t)
            if idf is None:
                continue
            for i, f in self.post[t]:
                dl = self.len[i] or 1
                acc[i] += idf * (f * (self.k1 + 1)) / (f + self.k1 * (1 - self.b + self.b * dl / self.avg))
        return acc

def main(corpus_path, checks_path, out_path, top_n=5):
    corpus = json.load(open(corpus_path))
    checks = json.load(open(checks_path))
    TITLE_WEIGHT = 4
    docs = [
        tokens(' '.join(c.get(f, '') for f in ('statement', 'objective', 'guidance')))
        + tokens(c.get('title', '')) * TITLE_WEIGHT
        for c in corpus
    ]
    idx = BM25(docs)
    per_field = {f: BM25([tokens(c.get(f, '')) for c in corpus]) for f in ('statement', 'objective', 'guidance')}

    out = {}
    for chk in checks:
        q = tokens(f"{chk.get('queryName','')} {chk.get('descriptionText','')} {chk.get('category','')}")
        acc = idx.score(q)
        if not acc:
            out[chk['id']] = {'query_name': chk.get('queryName'), 'candidates': [], 'review': REVIEW}
            continue
        cat = chk.get('category', '')
        acc = {i: apply_prior(sc, corpus[i]['control'], cat) for i, sc in acc.items()}
        top = sorted(acc.items(), key=lambda kv: -kv[1])[:top_n]
        best = top[0][1] or 1.0
        cands = []
        for i, s in top:
            matched = [f for f in ('statement', 'objective', 'guidance') if per_field[f].score(q).get(i, 0) > 0]
            cands.append({'control': corpus[i]['control'], 'control_title': corpus[i]['title'],
                          'score': round(s / best, 3), 'raw': round(s, 2), 'matched_on': matched})
        out[chk['id']] = {'query_name': chk.get('queryName'), 'platform': chk.get('platform'),
                          'cwe': chk.get('cwe'), 'category': chk.get('category'),
                          'candidates': cands, 'review': dict(REVIEW)}
    json.dump(out, open(out_path, 'w'), indent=2)
    print(f'checks scored: {len(out)} | with candidates: {sum(1 for v in out.values() if v["candidates"])}')

# Control families a check category can plausibly land in, and families it
# cannot. Purely lexical ranking matches "access" in a storage check to PE-3
# Physical Access Control; an explicit prior is more honest than a tuned
# similarity threshold, and a reviewer can argue with it.
FAMILY_PRIOR = {
    'Access Control':          (('AC', 'IA', 'SC'), ('PE', 'PS', 'PM', 'AT', 'MA', 'MP', 'PL')),
    'Encryption':              (('SC', 'SI', 'IA'), ('PE', 'PS', 'PM', 'AT', 'MA', 'PL', 'CP')),
    'Networking and Firewall': (('SC', 'AC'),       ('PE', 'PS', 'PM', 'AT', 'MA', 'MP', 'PL')),
    'Observability':           (('AU', 'SI', 'CA'), ('PE', 'PS', 'PM', 'AT', 'MA', 'MP')),
    'Secret Management':       (('IA', 'SC'),       ('PE', 'PS', 'PM', 'AT', 'MA', 'PL')),
    'Backup':                  (('CP', 'SI'),       ('PE', 'PS', 'PM', 'AT', 'MA')),
    'Availability':            (('CP', 'SC'),       ('PE', 'PS', 'PM', 'AT')),
    'Insecure Configurations': (('CM', 'SI', 'SC'), ('PE', 'PS', 'PM', 'AT', 'MA')),
    'Insecure Defaults':       (('CM', 'SI', 'SC'), ('PE', 'PS', 'PM', 'AT', 'MA')),
    'Resource Management':     (('CM', 'SC', 'SA'), ('PE', 'PS', 'AT')),
    'Supply-Chain':            (('SR', 'SA', 'CM'), ('PE', 'PS', 'AT')),
    'Bill Of Materials':       (('CM', 'SR', 'SA'), ('PE', 'PS', 'AT')),
    'Build Process':           (('SA', 'CM', 'SR'), ('PE', 'PS', 'AT')),
    'Best Practices':          (('CM', 'SA', 'SI'), ('PE', 'PS', 'AT')),
}
BOOST, PENALTY = 1.6, 0.25

def family(control):
    m = re.match(r'([A-Z]{2})', control)
    return m.group(1) if m else ''

def apply_prior(score, control, category):
    pref, avoid = FAMILY_PRIOR.get(category, ((), ()))
    f = family(control)
    if f in avoid:
        return score * PENALTY
    if f in pref:
        return score * BOOST
    return score

REVIEW = {'status': 'pending', 'reviewer': None, 'decided_utc': None, 'accepted': [], 'rejected': [], 'notes': None}

if __name__ == '__main__':
    main(*sys.argv[1:4])
