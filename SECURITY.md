# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

Use this section to tell people how to report a vulnerability.

Tell them where to go, how often they can expect to get an update on a
reported vulnerability, what to expect if the vulnerability is accepted or
declined, etc.
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_talisman import Talisman

app = Flask(__name__)
app.config['SECRET_KEY'] = 'votre_cle_secrete'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
csrf = CSRFProtect(app)  # Protection CSRF
login_manager = LoginManager(app)
talisman = Talisman(app)  # Active les en-têtes de sécurité (par exemple, Content-Security-Policy)

# Base de données d'utilisateurs (exemple)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
from werkzeug.security import generate_password_hash, check_password_hash

# Exemple d'enregistrement d'un utilisateur
hashed_password = generate_password_hash('monmotdepasse')
new_user = User(username='utilisateur', password=hashed_password)
db.session.add(new_user)
db.session.commit()

# Vérification du mot de passe lors de la connexion
if user and check_password_hash(user.password, 'motdepasse_donne'):
    login_user(user)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        # Sécuriser la gestion des mots de passe avec hashing
        if user and user.password == password:  # Comparer un mot de passe hashé
            login_user(user)
            flash('Connexion réussie!', 'success')
            return redirect(url_for('dashboard'))
        flash('Échec de la connexion. Veuillez vérifier vos identifiants.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Lancer l'application
if __name__ == "__main__":
    app.run(ssl_context='adhoc')  # Utilisation de HTTPS (avec certificat auto-signé pour test)
