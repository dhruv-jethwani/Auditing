from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), default='user')
    full_name = db.Column(db.String(150), nullable=True)
    phone = db.Column(db.String(15), nullable=True)
    age = db.Column(db.Integer, nullable=True)

    @staticmethod
    def hash_password(password):
        return generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(100), nullable=True)
    user_agent = db.Column(db.String(300), nullable=True)
    user = db.relationship('User', backref=db.backref('logs', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('register'))

        hashed_password = User.hash_password(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        if 'update_password' in request.form:
            old_password = request.form['old_password']
            new_password = request.form['new_password']

            if len(new_password) < 8:
                flash('New password must be at least 8 characters long.', 'danger')
                return redirect(url_for('profile'))

            if current_user.verify_password(old_password):
                current_user.password = User.hash_password(new_password)
                db.session.commit()
                log_activity(current_user, 'Password Updated')
                flash('Password updated successfully!', 'success')
            else:
                flash('Old password is incorrect!', 'danger')
        elif 'update_details' in request.form:
            current_user.full_name = request.form['full_name']
            current_user.phone = request.form['phone']
            current_user.age = request.form['age']
            db.session.commit()
            log_activity(current_user, 'Profile Details Updated')
            flash('Profile details updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html')

@app.route('/logs')
@login_required
def logs():
    if current_user.role != 'admin':
        flash('Access denied: Only admins can view logs.', 'danger')
        return redirect(url_for('home'))

    logs = Log.query.order_by(Log.timestamp.desc()).all()
    return render_template('logs.html', logs=logs)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):
            login_user(user)
            log_activity(user, 'Logged In')
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            if user:
                # If user exists but password is wrong
                log_activity(user, 'Failed Login Attempt')
            else:
                # Optional: log attempt with no matching user
                unknown_user = User(
                    username=username,
                    email='unknown@example.com',
                    password='',
                )
                db.session.add(unknown_user)
                db.session.flush()  # Get ID without committing fully
                log_activity(unknown_user, 'Failed Login Attempt: Unknown Username')
                db.session.rollback()  # Don't actually store this user
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    log_activity(current_user, 'Logged Out')
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

def log_activity(user, action):
    log = Log(user_id=user.id, action=action, ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent'))
    db.session.add(log)
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin_user').first():
            admin_user = User(
                username='admin_user',
                email='admin@example.com',
                password=User.hash_password('admin_password'),
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()
            print('Admin user created with username: admin_user and password: admin_password')
    app.run(debug=True)
