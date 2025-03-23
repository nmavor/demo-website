from flask import Flask, redirect, url_for, render_template, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from oauthlib.oauth2 import WebApplicationClient
from werkzeug.middleware.proxy_fix import ProxyFix
import requests
import os
import random
import string
from dotenv import load_dotenv
import base64
import validators
import tweepy



load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # Add this line after creating app
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Google Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# GitHub Configuration
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
# WordPress configuration
WORDPRESS_URL = os.getenv("WORDPRESS_URL")
WORDPRESS_APP_USERNAME = os.getenv("WORDPRESS_APP_USERNAME")
WORDPRESS_APP_PASSWORD = os.getenv("WORDPRESS_APP_PASSWORD")

client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Load X API credentials
X_API_BEARER_TOKEN = os.getenv("X_API_BEARER_TOKEN")
X_API_KEY = os.getenv("X_API_KEY")
X_API_SECRET = os.getenv("X_API_SECRET")
X_ACCESS_TOKEN = os.getenv("X_ACCESS_TOKEN")
X_ACCESS_TOKEN_SECRET = os.getenv("X_ACCESS_TOKEN_SECRET")

# Authenticate with X API using v2 (Bearer Token)
client = tweepy.Client(bearer_token=X_API_BEARER_TOKEN)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# New Submission model
class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    link = db.Column(db.String(200), nullable=False)
    kit = db.Column(db.String(50), nullable=False)
    code = db.Column(db.String(4), nullable=False)
    thumbnail = db.Column(db.String(200), nullable=True)

class Kit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database initialization
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email="admin@admin.com").first():
        admin = User(name="Admin", email="admin@admin.com", is_admin=True)
        db.session.add(admin)
    # Seed initial kits if none exist
    if not Kit.query.first():
        default_kits = ['kit1', 'kit2', 'kit3', 'kit4']
        for kit_name in default_kits:
            db.session.add(Kit(name=kit_name))
        db.session.commit()
        
def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

def generate_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

# Function to fetch thumbnail from X post
def get_x_thumbnail(url):
    try:
        # Extract the tweet ID from the URL (e.g., https://x.com/XXX/status/ID)
        if 'status' in url:
            tweet_id = url.split('status/')[-1].split('/')[0].split('?')[0]
        else:
            return None  # Not a valid X status URL

        # Fetch the tweet using the X API v2
        response = client.get_tweet(tweet_id, expansions=['attachments.media_keys'], media_fields=['url'])
        
        if response.data and response.includes and 'media' in response.includes:
            media = response.includes['media'][0]  # Get the first media item
            if media.type == 'photo':
                return media.url  # Return the full-size image URL
            elif media.type == 'video':
                # For videos, return the preview image (thumbnail)
                return media.preview_image_url if hasattr(media, 'preview_image_url') else None
        
        return None  # No media found
    except Exception as e:
        print(f"Error fetching thumbnail from X API: {e}")
        return None

    
# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin/user/<int:user_id>')
@login_required
def user_submissions(user_id):
    if not current_user.is_admin:
        return redirect(url_for('user_page'))
    user = User.query.get_or_404(user_id)
    submissions = Submission.query.filter_by(user_id=user_id).all()
    return render_template('user_submissions.html', user=user, submissions=submissions)

@app.route('/admin/user/<int:user_id>/submission/<int:submission_id>/delete', methods=['POST'])
@login_required
def delete_submission(user_id, submission_id):
    if not current_user.is_admin:
        flash("You do not have permission to delete submissions", "error")
        return redirect(url_for('user_page'))
    
    submission = Submission.query.get_or_404(submission_id)
    if submission.user_id != user_id:
        flash("Invalid submission for this user", "error")
        return redirect(url_for('user_submissions', user_id=user_id))
    
    db.session.delete(submission)
    db.session.commit()
    flash("Submission deleted successfully", "success")
    return redirect(url_for('user_submissions', user_id=user_id))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login/google')
def google_login():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    
    # Manually construct the authorization URL
    authorization_url = f"{authorization_endpoint}?client_id={GOOGLE_CLIENT_ID}&redirect_uri={url_for('google_callback', _external=True, _scheme='https')}&scope=openid+email+profile&response_type=code"
    return redirect(authorization_url)

@app.route('/login/google/callback')
def google_callback():
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    
    # Manually construct the token request
    token_data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': url_for('google_callback', _external=True, _scheme='https'),
        'grant_type': 'authorization_code'
    }
    
    token_response = requests.post(
        token_endpoint,
        data=token_data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    
    if token_response.status_code == 200:
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        
        # Use the access token to fetch user info
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        headers = {'Authorization': f'Bearer {access_token}'}
        userinfo_response = requests.get(userinfo_endpoint, headers=headers)
        
        if userinfo_response.json().get("email_verified"):
            users_email = userinfo_response.json()["email"]
            users_name = userinfo_response.json()["name"]
            
            user = User.query.filter_by(email=users_email).first()
            if not user:
                user = User(email=users_email, name=users_name)
                db.session.add(user)
                db.session.commit()
            
            login_user(user)
            return redirect(url_for("user_page"))
    else:
        flash("Failed to authenticate with Google", "error")
        return redirect(url_for("login"))

@app.route('/login/github')
def github_login():
    return redirect(f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={url_for('github_callback', _external=True)}")

@app.route('/login/github/callback')
def github_callback():
    code = request.args.get('code')
    token_url = "https://github.com/login/oauth/access_token"
    response = requests.post(token_url, data={
        'client_id': GITHUB_CLIENT_ID,
        'client_secret': GITHUB_CLIENT_SECRET,
        'code': code
    }, headers={'Accept': 'application/json'})
    
    access_token = response.json()['access_token']
    user_response = requests.get('https://api.github.com/user', headers={'Authorization': f'token {access_token}'})
    user_data = user_response.json()
    
    users_email = user_data.get('email') or f"{user_data['login']}@github.com"
    users_name = user_data.get('name') or user_data['login']
    
    user = User.query.filter_by(email=users_email).first()
    if not user:
        user = User(email=users_email, name=users_name)
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    return redirect(url_for("user_page"))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'admin':
            admin = User.query.filter_by(email="admin@admin.com").first()
            login_user(admin)
            return redirect(url_for('admin_page'))
        return "Invalid credentials"
    return render_template('admin_login.html')

@app.route('/user', methods=['GET', 'POST'])
@login_required
def user_page():
    if request.method == 'POST':
        link = request.form.get('link')
        kit = request.form.get('kit')
        
        if link and kit:
            if not link.startswith(('http://', 'https://')):
                link = f"https://{link}"
            if not validators.url(link):
                flash("Please enter a valid URL (e.g., https://example.com)", "error")
                return redirect(url_for('user_page'))
            
            # Check if it's an X post and fetch thumbnail
            thumbnail = None
            if 'x.com' in link or 'twitter.com' in link:  # X posts might still use twitter.com
                thumbnail = get_x_thumbnail(link)
            
            code = generate_code()
            submission = Submission(
                user_id=current_user.id,
                link=link,
                kit=kit,
                code=code,
                thumbnail=thumbnail
            )
            db.session.add(submission)
            db.session.commit()
            
            flash(f"Your next code is {code}", "success")
            return redirect(url_for('user_page'))
        
        flash("Please fill in all fields", "error")
    
    kits = [kit.name for kit in Kit.query.all()]
    return render_template('user.html', name=current_user.name, kits=kits)


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_page():
    if not current_user.is_admin:
        return redirect(url_for('user_page'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            new_kit = request.form.get('new_kit')
            if new_kit and new_kit not in [kit.name for kit in Kit.query.all()]:
                db.session.add(Kit(name=new_kit))
                db.session.commit()
                flash(f"Added kit: {new_kit}", "success")
            else:
                flash("Kit name is empty or already exists", "error")
        elif action == 'delete':
            kit_id = request.form.get('kit_id')
            kit = Kit.query.get(kit_id)
            if kit:
                # Check if kit is used in submissions
                if not Submission.query.filter_by(kit=kit.name).first():
                    db.session.delete(kit)
                    db.session.commit()
                    flash(f"Deleted kit: {kit.name}", "success")
                else:
                    flash("Cannot delete kit in use by submissions", "error")
            else:
                flash("Kit not found", "error")
    
    users = User.query.all()
    kits = Kit.query.all()
    return render_template('admin.html', users=users, kits=kits)

@app.route('/login/wordpress', methods=['GET', 'POST'])
def wordpress_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # WordPress REST API authentication
        auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers = {
            'Authorization': f'Basic {auth}',
            'User-Agent': 'Flask App'
        }
        response = requests.get(f"{WORDPRESS_URL}/wp-json/wp/v2/users/me", headers=headers)
        
        if response.status_code == 200:
            wp_user = response.json()
            email = wp_user.get('email', f"{wp_user['slug']}@wordpress.local")
            name = wp_user.get('name', wp_user['slug'])
            
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(email=email, name=name)
                db.session.add(user)
                db.session.commit()
            
            login_user(user)
            return redirect(url_for('user_page'))
        
        flash("Invalid WordPress credentials", "error")
    
    return render_template('wordpress_login.html')



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

    