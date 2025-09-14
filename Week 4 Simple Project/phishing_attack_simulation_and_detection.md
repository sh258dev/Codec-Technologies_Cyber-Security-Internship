# Phishing Attack Simulation and Detection

**Objective:** Simulate phishing attacks to test awareness and implement detection mechanisms (email filters, fake website detection).

**Tools:** Phishing simulation tools (GoPhish, King Phisher), email security tools, Python.

**Skills Learned:** Phishing techniques, email security, detection systems.

---

## 1) High-level project plan (phases)

1. **Planning & legal/ethics**
   - Get written approval from org owners / legal.
   - Define scope (who can be tested, excluded groups, allowed time windows).
   - Prepare communications: opt-out, post-test debrief & training.
2. **Simulation design**
   - Decide phishing scenarios (credential harvest, invoice, HR, etc.), risk level (low/medium/high).
   - Create controlled landing pages and templates (safe, data not actually harvested).
3. **Baseline & tooling**
   - Deploy simulation tooling in an isolated environment.
   - Set up logging, captured metrics, and rollback plans.
4. **Run pilot**
   - Small cohort pilot; check delivery, filtering, logging.
5. **Full campaign**
   - Execute per scope; monitor in real time for misdelivery or false positives.
6. **Detection & response**
   - Use email filters, inbox rules, and detection algorithms. Log hits.
7. **Analysis & training**
   - Analyse results, compute metrics, run targeted awareness sessions.
8. **Remediation & repeat**
   - Patch issues (mailserver config, DMARC, user training) and run iterative tests.

---

## 2) Ethical & legal checklist (must do)

- Written authorization from senior management & legal.
- Notify IT/security teams and maintain a “kill-switch.”
- Use only organization-owned domains or explicitly provisioned domains and assets.
- Don’t collect real credentials — simulate or store safely and delete after test.
- Inform users after the test (debrief + training materials).
- Keep data private and delete logs per policy.

---

## 3) Tools & stack (defensive / testing)

- **Phishing simulation platforms (for authorized testing):** GoPhish (open-source), King Phisher.
- **Mail gateway / filtering:** Postfix/Exim + SpamAssassin, Rspamd, MimeDefang.
- **Authentication checks:** OpenDKIM, OpenDMARC, OpenSPF (or built-in MTA features).
- **Endpoint/URL scanning:** Sandboxing (Cuckoo or enterprise URL scanners).
- **Threat intelligence / domain checks:** Passive DNS, WHOIS age checks, public blacklists.
- **Malware/attachment scanning:** ClamAV or enterprise AV with detonation sandbox.
- **Logging/analytics:** ELK/Opensearch, Splunk, or a simple DB + dashboards.

---

## 4) Detection approaches (multi-layered)

1. **Authentication checks** — Enforce/monitor SPF, DKIM, DMARC; treat failures as high risk.
2. **Header & envelope analysis** — Mismatch between MAIL FROM and Return-Path, suspicious Received path.
3. **Link & domain analysis** — URL vs visible text mismatch; domain age; homograph/typo-squatting checks; use blacklists/allowlists and sandboxing.
4. **Content/lexical features** — Urgency language, call-to-action verbs, presence of login forms, obfuscated links.
5. **Attachment/filename checks** — Double extensions, macros in Office docs, executable attachments.
6. **Visual / similarity detection** — Image/page hashing or machine vision to detect logo impersonation.
7. **Behavioral detection** — Redirect chains, form submissions, credential-entry events.
8. **Machine learning** — Combine features into classifiers (logistic regression / random forest / lightGBM).
9. **User awareness signals** — Track reporting rate of users.

---

## 5) Experiment design & success metrics

- **Cohorts:** control (no training) vs trained group.
- **Metrics:**
  - Delivery rate (emails delivered vs blocked).
  - Click-through rate (CTR).
  - Submission rate (simulated credential submission).
  - Reporting rate (users reporting the email).
  - False positive rate of detection systems.
  - Time-to-detect / time-to-remediate.
- **Goals:** e.g., reduce CTR by X% after training; increase reporting rate to Y%.

---

## 6) Data you should collect (safely)

- Timestamps, recipient hashes (avoid plain PII), original email headers, clicked-URL hashes, detection flags (SPF/DKIM/DMARC), whether user reported the email, campaign metadata.

---

## 7) Safe Python prototype — feature extraction + small classifier

This compact example extracts simple features from raw email text (headers/body), computes heuristic features, and trains a small classifier on synthetic labeled data. **For detection only.**

```python
# Python 3 — run locally in a controlled environment.
# Requires: pandas, scikit-learn, beautifulsoup4
# pip install pandas scikit-learn beautifulsoup4

import re
import pandas as pd
from bs4 import BeautifulSoup
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# ----- simple feature extractor -----
def extract_features(email_text):
    # naive split: assume we get headers and body separated by blank line
    parts = email_text.split("\n\n", 1)
    headers = parts[0] if parts else ""
    body = parts[1] if len(parts) > 1 else ""
    features = {}
    features['len_body'] = len(body)
    # count URLs
    urls = re.findall(r'https?://[^\s"\'>]+', body, flags=re.I)
    features['num_urls'] = len(urls)
    # visible-text vs href mismatch (rudimentary)
    soup = BeautifulSoup(body, "html.parser")
    mismatch = 0
    for a in soup.find_all('a', href=True):
        text = (a.get_text() or "").strip()
        href = a['href'].strip()
        if text and not href.endswith(text) and re.search(r'http', text, flags=re.I) is None:
            mismatch += 1
    features['anchor_mismatch_count'] = mismatch
    # urgent words
    urgent_words = re.findall(r'\b(urgent|immediately|asap|verify|password|reset|account|suspend|click here)\b', body, flags=re.I)
    features['urgent_word_count'] = len(urgent_words)
    # presence of login form
    features['has_form'] = 1 if bool(soup.find('form')) else 0
    # attachments hint (naive)
    features['attachment_like'] = 1 if re.search(r'Content-Disposition: attachment', headers, flags=re.I) else 0
    return features

# ----- toy dataset (replace with proper labeled dataset in production) -----
# Create synthetic examples: 0 = legitimate, 1 = phishing
examples = []
labels = []

# legitimate example
legit_email = """From: billing@vendor.example
To: user@example.com

Hello,
Your invoice is attached. Thank you.
<a href="https://portal.vendor.example">View invoice</a>
"""
examples.append(legit_email); labels.append(0)

# phishing example: link mismatch, urgent words, form
phish_email = """From: security-alerts@some-rnd-domain.com
To: user@example.com

Dear user, your account will be suspended. Verify immediately.
<a href="http://tiny-evil.example/login">Click here to verify</a>
<form action="http://tiny-evil.example/collect"><input name="username"/></form>
"""
examples.append(phish_email); labels.append(1)

# add a few copies with minor variations to build a tiny dataset
for i in range(10):
    examples.append(legit_email); labels.append(0)
    examples.append(phish_email); labels.append(1)

# build dataframe
rows = []
for e, lab in zip(examples, labels):
    f = extract_features(e)
    f['label'] = lab
    rows.append(f)
df = pd.DataFrame(rows)

# train/test
X = df.drop(columns=['label'])
y = df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, random_state=42, test_size=0.3)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)

print(classification_report(y_test, y_pred, digits=3))
print("Feature importances:")
print(sorted(zip(X.columns, clf.feature_importances_), key=lambda x: x[1], reverse=True))
```

**Notes on the prototype:**
- Replace the synthetic dataset with a properly labeled dataset (organization-specific samples, safely anonymized).
- Add SPF/DKIM/DMARC checks by parsing headers and using external libraries or mailserver reports; treat auth failures as strong features.
- For production use: use cross-validation, better feature engineering (TF-IDF on body, domain reputation lookups, WHOIS features, cert checks), and tune thresholds to minimize false positives.

---

## 8) Practical deployment tips

- **Mail server hardening:** enforce DMARC reject/quarantine progressively (start with p=none to monitor, then quarantine/reject when safe).
- **Quarantine policy:** keep suspicious mails in quarantine and notify users with a safe preview + report button.
- **Automated triage:** block known-bad hashes/domains, sandbox attachments, and automatically tag suspicious emails for human review.
- **User reporting:** add one-click “report phishing” that sends original headers to security team (and auto-submits to internal triage queue).
- **Training linkage:** integrate immediate microlearning pop-ups for users who clicked (short 2–3 minute module).

---

## 9) After-action: analysis & learning

- Provide personalized feedback (not public shaming).
- Share aggregated dashboards: CTR, reporting rate, segmentation by department.
- Create targeted training for the most at-risk groups and repeat tests every 3–6 months.

---

## 10) Quick risk & safety reminders

- Never harvest real credentials.
- Don’t impersonate emergency services, law enforcement, or any content that could cause panic.
- Keep simulations reversible and non-destructive.



