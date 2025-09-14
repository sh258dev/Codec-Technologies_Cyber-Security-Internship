# Building a Secure Web Application

**Objective:** Create a simple web application and implement security measures like authentication, authorization, and secure data storage.

**Tools:** Flask or Django (Python), Node.js (Express), OAuth, JWT, parameterized SQL libraries, password hashing libraries (bcrypt), and security linters.

**Skills Learned:** Web security fundamentals, secure coding practices, OWASP Top 10 mitigation, authentication & authorization, secure data storage.

---

## 1) Project overview & deliverables

Build a small web application (e.g., task manager or notes app) with:
- User registration & login
- Role-based access control (user vs admin)
- Secure password storage
- Protected API endpoints (JWT or session-based)
- Input validation and SQL injection prevention
- Secure configuration and deployment checklist

Deliverables:
- Working app (Flask or Django) with a README
- Security checklist and test cases
- Short report showing OWASP Top 10 mitigations implemented

---

## 2) High-level plan (phases)
1. **Design & requirements** — define features, user flows, data model, threat model and assets.
2. **Setup & scaffolding** — pick framework (Flask recommended for learning; Django for batteries-included), create repo, virtualenv, basic routes.
3. **Implement authentication** — registration, login, password hashing, email verification (optional).
4. **Implement authorization** — role checks, per-resource ACLs.
5. **Secure data handling** — parameterized queries/ORM, encrypt sensitive fields at rest.
6. **Input validation & output encoding** — prevent XSS and injection.
7. **Testing & hardening** — run static analysis, dependency checks, pen-tests.
8. **Deployment** — secure server, HTTPS, secrets management, logging & monitoring.

---

## 3) Threat modeling (brief)
- Identify assets: user credentials, personal data, session tokens, DB.
- Potential threats: SQL injection, XSS, CSRF, broken auth, insecure direct object references, sensitive data exposure.
- Prioritize defenses by impact & likelihood.

---

## 4) Recommended stack & libs
- **Python / Flask**: Flask, Flask-Login, Flask-JWT-Extended, SQLAlchemy, Alembic, bcrypt.
- **Python / Django**: Django (auth built-in), django-rest-framework, django-axes (rate-limit), django-environ.
- **Node.js**: Express, Passport.js (OAuth), jsonwebtoken, Sequelize/TypeORM for ORM, bcrypt.
- **DB**: PostgreSQL (prefer), use parameterized queries; avoid raw string SQL.
- **Dev tools**: Bandit (Python security linter), Snyk/Dependabot for deps, OWASP ZAP for scanning.

---

## 5) Concrete secure implementation (Flask example)

Below is a minimal secure Flask blueprint demonstrating registration, login (password hashing with bcrypt), JWT issuance, role-based decorator, and parameterized DB access using SQLAlchemy.

> NOTE: run locally in a virtualenv. This is a starter example; remove debug mode before deployment.

```python
# app.py — minimal Flask app with SQLAlchemy & JWT
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL','sqlite:///data.db')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY','change-me')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ----- models -----
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')

    def check_password(self, pw):
        return bcrypt.check_password_hash(self.password_hash, pw)

# ----- utilities -----
def role_required(role):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            uid = get_jwt_identity()
            user = User.query.get(uid)
            if not user or user.role != role:
                return jsonify({'msg':'forbidden'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ----- routes -----
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'msg':'username and password required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'msg':'user exists'}), 400
    pw_hash = bcrypt.generate_password_hash(password).decode()
    u = User(username=username, password_hash=pw_hash)
    db.session.add(u)
    db.session.commit()
    return jsonify({'msg':'registered'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'msg':'bad credentials'}), 401
    access = create_access_token(identity=user.id)
    return jsonify({'access_token': access}), 200

@app.route('/admin-only')
@role_required('admin')
def admin_only():
    return jsonify({'secret':'only for admins'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
```

**Security notes for the sample:**
- Passwords hashed with bcrypt.
- JWT secret loaded from environment.
- SQLAlchemy prevents SQL injection via parameterization by default.
- Role-based decorator enforces simple RBAC.

---

## 6) OWASP Top 10 – mitigations mapping (short)
- **A1: Injection** — use parameterized queries/ORM; validate inputs.
- **A2: Broken Authentication** — secure password storage, multi-factor, session invalidation.
- **A3: Sensitive Data Exposure** — encrypt sensitive fields, TLS in transit.
- **A4: XML External Entities (XXE)** — disable XML parsing or harden parsers.
- **A5: Broken Access Control** — enforce server-side authorization checks.
- **A6: Security Misconfiguration** — avoid debug; keep secrets out of code.
- **A7: Cross-Site Scripting (XSS)** — output-encode, Content Security Policy (CSP).
- **A8: Insecure Deserialization** — avoid `pickle`; use safe serializers.
- **A9: Using Components with Known Vulnerabilities** — scan deps, pin versions.
- **A10: Insufficient Logging & Monitoring** — implement audit logs and alerts.

---

## 7) Additional hardening & deployment checklist
- Use HTTPS everywhere (Let’s Encrypt) and HSTS.
- Store secrets in environment variables or a secrets manager (Vault, AWS Secrets Manager).
- Turn off debug modes and detailed error pages in production.
- Use secure headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
- Limit rate for auth endpoints and apply account lockout / throttling.
- Regularly run dependency vulnerability scans.
- Implement centralized logging and alerting; protect logs from tampering.
- Back up database and test restore procedures.

---

## 8) Testing & validation
- **Static Analysis:** Bandit, ESLint, TypeScript checks.
- **Dependency Scanning:** Snyk, Dependabot.
- **Dynamic Analysis:** OWASP ZAP automated scans against staging.
- **Fuzzing & Inputs:** test for unexpected input sizes, types.
- **Penetration Testing:** focus on auth flows, file upload endpoints, IDOR tests.
- **Unit & Integration Tests:** include security-focused test cases (e.g., ensure endpoints reject unauthorized access).

---

## 9) Example security-focused test cases
- Registration: passwords with weak strength refused.
- Login: repeated failed logins trigger rate limiting.
- API: protected endpoints return 401/403 for unauthenticated/unauthorized.
- SQL injection: payloads injected into inputs do not change DB schema or query logic.
- XSS: stored and reflected inputs are sanitized and CSP blocks inline scripts.

---

## 10) Learning resources
- OWASP Top Ten: https://owasp.org/www-project-top-ten/
- Flask Security Patterns: https://flask.palletsprojects.com/
- Django Security: https://docs.djangoproject.com/en/stable/topics/security/
- Web security learning: OWASP Juice Shop (vulnerable app for learning)

---

## 11) Next steps 
- A step-by-step deployment guide to deploy the app securely on AWS/GCP using HTTPS and managed DB.


