from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
import os
from dotenv import load_dotenv
from io import BytesIO
import base64
import hashlib
import json
import time
from datetime import datetime

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Blockchain implementation
class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.create_block(previous_hash='1', proof=100)

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]) if self.chain else None,
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, certificate_hash):
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'certificate_hash': certificate_hash,
            'timestamp': time.time()
        })
        return self.last_block['index'] + 1 if self.chain else 1

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1] if self.chain else None

    def proof_of_work(self, last_proof):
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

blockchain = Blockchain()

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    certificates = db.relationship('Certificate', backref='issuer', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Certificate model
class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    recipient_name = db.Column(db.String(100), nullable=False)
    recipient_email = db.Column(db.String(120), nullable=False)
    recipient_date_of_birth = db.Column(db.Date, nullable=False)
    recipient_address = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    qr_code = db.Column(db.String(200))
    blockchain_hash = db.Column(db.String(64), unique=True, nullable=False)
    issued_date = db.Column(db.DateTime, default=datetime.now)
    is_verified = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CertificateForm(FlaskForm):
    title = StringField('Certificate Title', validators=[DataRequired()])
    recipient_name = StringField('Recipient Name', validators=[DataRequired()])
    recipient_email = StringField('Recipient Email', validators=[DataRequired(), Email()])
    recipient_date_of_birth = StringField('Recipient Date of Birth (YYYY-MM-DD)', validators=[DataRequired()])
    recipient_address = StringField('Recipient Address', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Issue Certificate')

class VerifyCertificateForm(FlaskForm):
    certificate_hash = StringField('Certificate Hash or QR Code', validators=[DataRequired()])
    submit = SubmitField('Verify')

# QR Code generation
def generate_qr_code(certificate_hash):
    # Use a public IP address or domain name
    base_url = request.url_root.replace('127.0.0.1', 'YOUR_PUBLIC_IP_OR_DOMAIN_NAME')
    certificate_url = f"{base_url}certificate/{certificate_hash}"
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(certificate_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return img_str

# Hash utility
def generate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Routes
@app.route('/')
def home():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Email address already exists. Please use a different email address.', 'danger')
            return redirect(url_for('register'))
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred while creating your account. Please try again.', 'danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    certificates = Certificate.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', certificates=certificates)

@app.route('/issue_certificate', methods=['GET', 'POST'])
@login_required
def issue_certificate():
    form = CertificateForm()
    if form.validate_on_submit():
        certificate_hash = generate_hash(f"{form.title.data}{form.recipient_name.data}{form.recipient_email.data}{form.recipient_date_of_birth.data}{form.recipient_address.data}{form.description.data}")
        blockchain.new_transaction(
            sender=current_user.username,
            recipient=form.recipient_name.data,
            certificate_hash=certificate_hash
        )
        last_proof = blockchain.last_block['proof'] if blockchain.last_block else 100
        proof = blockchain.proof_of_work(last_proof)
        previous_hash = blockchain.hash(blockchain.last_block) if blockchain.last_block else '1'
        blockchain.create_block(proof, previous_hash)
        qr_code = generate_qr_code(certificate_hash)
        certificate = Certificate(
            title=form.title.data,
            recipient_name=form.recipient_name.data,
            recipient_email=form.recipient_email.data,
            recipient_date_of_birth=datetime.strptime(form.recipient_date_of_birth.data, '%Y-%m-%d'),
            recipient_address=form.recipient_address.data,
            description=form.description.data,
            qr_code=qr_code,
            blockchain_hash=certificate_hash,
            user_id=current_user.id
        )
        db.session.add(certificate)
        db.session.commit()
        flash('Certificate issued successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('issue_certificate.html', form=form)

@app.route('/certificate/<string:certificate_hash>')
def view_certificate_by_hash(certificate_hash):
    certificate = Certificate.query.filter_by(blockchain_hash=certificate_hash).first_or_404()
    return render_template('certificate.html', certificate=certificate)

@app.route('/verify_certificate', methods=['GET', 'POST'])
def verify_certificate():
    form = VerifyCertificateForm()
    if form.validate_on_submit():
        certificate_hash = form.certificate_hash.data
        certificate = Certificate.query.filter_by(blockchain_hash=certificate_hash).first()
        if certificate:
            return render_template('certificate.html', certificate=certificate)
        else:
            flash('Certificate not found. Please check the hash or QR code.', 'danger')
    return render_template('verify_certificate.html', form=form)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)