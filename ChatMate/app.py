
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_bcrypt import Bcrypt  # Import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from dotenv import load_dotenv
import os
from supabase import create_client, Client
import secrets
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
from functools import wraps

import cloudinary
from cloudinary.uploader import upload
from cloudinary.utils import cloudinary_url



#4no requirement
from flask import Flask, request, render_template
import pandas as pd
import requests
import io
import langdetect
from langdetect import detect
import matplotlib.pyplot as plt
import base64
from collections import Counter
import langid
import base64
import seaborn as sns


# Load environment variables
load_dotenv()








# Configure Cloudinary
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)


# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Supabase URL or API Key is missing. Check your .env file.")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Initialize Flask
app = Flask(__name__)
app.secret_key = SECRET_KEY  # Set the secret key for Flask sessions

# Initialize Flask-Bcrypt
bcrypt = Bcrypt(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'






#4no requirement
# CSV File URL
csv_url = "https://raw.githubusercontent.com/connect2robiul/CSVfile/refs/heads/master/RafigCovid_19.csv"

def process_csv():
    try:
        # ✅ Read CSV with correct separator
        df = pd.read_csv(csv_url, sep=";", encoding="utf-8", engine="python")

        # ✅ Check column names
        print("Column Names:", df.columns)

        # ✅ Ensure the correct text column is used for language detection
        text_column = "Tweet"  # Modify if necessary

        if text_column not in df.columns:
            raise ValueError(f"Column '{text_column}' not found in CSV!")

        # ✅ Detect languages
        df["language"] = df[text_column].astype(str).apply(lambda x: langid.classify(x)[0])

        # ✅ Get unique languages & assign colors dynamically
        unique_languages = df["language"].unique()
        color_palette = sns.color_palette("husl", len(unique_languages))

        language_colors = {
            lang: "#{:02x}{:02x}{:02x}".format(int(r*255), int(g*255), int(b*255))
            for lang, (r, g, b) in zip(unique_languages, color_palette)
        }

        # ✅ Generate histogram
        plt.figure(figsize=(10, 5))
        df["language"].value_counts().plot(kind="bar", color=[language_colors[lang] for lang in df["language"].unique()])
        plt.xlabel("Language")
        plt.ylabel("Count")
        plt.title("Language Frequency Histogram")

        # ✅ Convert plot to base64 image
        img = io.BytesIO()
        plt.savefig(img, format="png")
        img.seek(0)
        histogram_img = base64.b64encode(img.getvalue()).decode()

        return df, language_colors, histogram_img

    except Exception as e:
        print(f"❌ Error: {e}")
        return None, None, None

@app.route("/statuses")
def statuses():
    df, language_colors, histogram_img = process_csv()

    if df is None:
        return "Error processing CSV file. Check logs."

    return render_template("statuses.html", languages=language_colors, histogram_img=histogram_img)

'''
#testing
import smtplib
from email.mime.text import MIMEText

# Email configuration
sender_email = "chatmate051@gmail.com"
receiver_email = "ielahi61@@gmail.com"
password = "qxmnq bppr lkpt tctvyour-app-password"  # Use the app password

# Create the email
subject = "Test Email"
body = "This is a test email sent using Python."
msg = MIMEText(body)
msg['Subject'] = subject
msg['From'] = sender_email
msg['To'] = receiver_email

# Send the email
try:
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()  # Upgrade the connection to secure
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
    print("Email sent successfully!")
except Exception as e:
    print(f"Failed to send email: {e}")
#############
'''



class User(UserMixin):
    def __init__(self, id, username, name, email, password_hash, email_verified=False, role_id=None, profile_picture_url=None):
        self.id = id
        self.username = username
        self.name = name
        self.email = email
        self.password_hash = password_hash
        self.email_verified = email_verified
        self.role_id = role_id
        self.profile_picture_url = profile_picture_url

    def __repr__(self):
        return f"<User {self.name}>"

    def check_password(self, password):
        # Use bcrypt to check the password hash
        return bcrypt.check_password_hash(self.password_hash, password)

    def has_permission(self, permission_name):
        # Fetch permissions for the user's role
        response = supabase.table('permissions').select('permission_name').eq('role_id', self.role_id).execute()
        permissions = [perm['permission_name'] for perm in response.data]
        return permission_name in permissions

    def get_permissions(self):
        # Fetch all permissions for the user's role
        response = supabase.table('permissions').select('permission_name').eq('role_id', self.role_id).execute()
        return [perm['permission_name'] for perm in response.data] if response.data else []

    def get_role_name(self):
        if not self.role_id:
            return "Unknown Role"  # Return a default role name if role_id is None

        response = supabase.table('roles').select('name').eq('id', self.role_id).execute()
        if response.data:
            return response.data[0]['name']
        return "Unknown Role"
    
    @staticmethod
    def get_by_email(email):
        try:
            # Execute the Supabase query
            response = supabase.table("users").select("*").eq("email", email).execute()

            # Check if the response was successful and contains data
            if response and response.data:
                user_data = response.data[0]
                # Filter out the 'password' field (if it exists)
                filtered_data = {
                    "id": user_data["id"],
                    "username": user_data["username"],
                    "name": user_data["name"],
                    "email": user_data["email"],
                    "password_hash": user_data["password_hash"],
                    "email_verified": user_data.get("email_verified", False),
                    "role_id": user_data.get("role_id")  # Fetch role_id
                }
                return User(**filtered_data)  # Create User instance from filtered data

        except Exception as e:
            # Log an error for debugging purposes
            print(f"Error fetching user by email '{email}': {e}")

        # Return None if the user does not exist or an error occurred
        return None

    @staticmethod
    def get_by_id(user_id):
        response = supabase.table("users").select("*").eq("id", user_id).execute()
        if response.data:
            user_data = response.data[0]
            return User(
                id=user_data["id"],
                username=user_data["username"],
                name=user_data["name"],
                email=user_data["email"],
                password_hash=user_data["password_hash"],
                email_verified=user_data.get("email_verified", False),
                role_id=user_data.get("role_id"),
                profile_picture_url=user_data.get("profile_picture_url")  # Ensure this is included
            )
        return None

    @staticmethod
    def log_session(user_id):
        """Log user login session in the database."""
        try:
            response = supabase.table('user_logins').insert({
                'userid': user_id,
                'login_timestamp': 'now()',  # Automatically set the current timestamp
                'ip_address': request.remote_addr,  # Log the user's IP address
                'user_agent': request.headers.get('User-Agent')  # Log the user's browser/device info
            }).execute()
            return response.data
        except Exception as e:
            print(f"Error logging session: {e}")
            return None

    # def set_remember_me_token(self, token):
    #     try:
    #         # Hardcode a token for testing
    #         test_token = "test_token_123"
    #         response = supabase.table('users').update({
    #             'remember_me_token': test_token
    #         }).eq('id', self.id).execute()
    #         print(f"Updated remember_me_token for user {self.id}: {test_token}")  # Debugging
    #         return response.data
    #     except Exception as e:
    #         print(f"Error setting remember me token: {e}")
    #         return None

    def set_remember_me_token(self, token):
        """Store the 'Remember Me' token in the database."""
        try:
            response = supabase.table('users').update({
                'remember_me_token': token
            }).eq('id', self.id).execute()
            return response.data
        except Exception as e:
            print(f"Error setting remember me token: {e}")
            return None

    @staticmethod
    def get_by_remember_me_token(token):
        """Fetch a user by their 'Remember Me' token."""
        try:
            response = supabase.table('users').select('*').eq('remember_me_token', token).execute()
            if response.data:
                user_data = response.data[0]
                return User(**user_data)
        except Exception as e:
            print(f"Error fetching user by remember me token: {e}")
        return None
    
# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)
        
# Home route
@app.route('/')
def home():
    if current_user.is_authenticated:
        # Redirect based on user role
        role_name = current_user.get_role_name()
        if role_name == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role_name == 'user':
            return redirect(url_for('user_dashboard'))
        elif role_name == 'guest':
            return redirect(url_for('guest_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    return render_template('index.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember_me = 'remember_me' in request.form  # Check if "Remember Me" is selected

        user = User.get_by_email(email)

        if user and user.check_password(password):
            # Generate and store the remember_me_token if "Remember Me" is checked
            if remember_me:
                token = generate_remember_me_token(user.email)  # Generate the token
                user.set_remember_me_token(token)  # Store the token in the database

            # Log in the user with Flask-Login
            login_user(user, remember=remember_me)  # Enable remember_me
            session.permanent = True  # Enable session expiry
            User.log_session(user.id)
            flash('Logged in successfully!', 'success')

            # Redirect based on user role
            role_name = user.get_role_name()
            if role_name == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif role_name == 'user':
                return redirect(url_for('user_dashboard'))
            elif role_name == 'guest':
                return redirect(url_for('guest_dashboard'))
            else:
                return redirect(url_for('dashboard'))

        else:
            flash('Invalid email or password!', 'danger')

    return render_template('login.html')

def generate_remember_me_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    token = serializer.dumps(email, salt='remember-me')
    print(f"Generated token: {token}")  # Debugging
    return token
# Logout Route
@app.route('/logout')
@login_required
def logout():
    # Update the logout_timestamp for the current session
    try:
        response = supabase.table('user_logins').update({
            'logout_timestamp': 'now()'  # Use 'now()' to set the current timestamp
        }).eq('userid', current_user.id).is_('logout_timestamp', 'NULL').execute()

        if response.data:
            flash('Logged out successfully!', 'success')
        else:
            flash('No active session found.', 'info')
    except Exception as e:
        flash(f"Error logging out: {str(e)}", 'danger')

    logout_user()  # Clear the Flask-Login session
    return redirect(url_for('home'))

# Signup Route..................................
app.config['MAIL_DEBUG'] = True  # testing


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'chatmate051@gmail.com'
app.config['MAIL_PASSWORD'] = 'xejn dnvx pgku uive' #App Password
mail = Mail(app)
from flask_mail import Message

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Check if email or username already exists
        response = supabase.table('users').select('email, username').or_(f'email.eq.{email},username.eq.{username}').execute()
        if response.data:
            flash('Email or username already exists.', 'danger')
            return redirect(url_for('signup'))

        # Fetch the default role_id for 'user'
        role_response = supabase.table('roles').select('id').eq('name', 'user').execute()
        if not role_response.data:
            flash('Default role not found. Please contact the administrator.', 'danger')
            return redirect(url_for('signup'))

        role_id = role_response.data[0]['id']  # Assign the default role ID

        # Hash the password
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert user into the database
        try:
            response = supabase.table('users').insert({
                'username': username,
                'name': name,
                'email': email,
                'password_hash': password_hash,
                'email_verified': False,
                'role_id': role_id  # Assign the default role ID
            }).execute()

            if response.data:
                flash('Account created successfully! Please check your email to verify your account.', 'success')

                # Generate email verification token
                token = generate_verification_token(email)
                verification_url = url_for('verify_email', token=token, _external=True)

                # Send verification email
                try:
                    msg = Message("Verify Your Email", sender="your-email@gmail.com", recipients=[email])
                    msg.body = f"Click the link to verify your email: {verification_url}"
                    mail.send(msg)
                    flash('Verification email sent!', 'success')
                except Exception as e:
                    flash(f"Failed to send email: {str(e)}", 'danger')
                    print(f"Error sending email: {str(e)}")

                return redirect(url_for('login'))
            else:
                flash('Failed to create an account. Try again.', 'danger')
        except Exception as e:
            flash(f"Error: {str(e)}", 'danger')

    return render_template('signup.html')

# Protected Route (Dashboard)
@app.route('/dashboard')
@login_required
def dashboard():
    # Refresh user data from the database
    user = User.get_by_id(current_user.id)  # Fetch the latest user data
    role_name = user.get_role_name()
    if role_name == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role_name == 'user':
        return redirect(url_for('user_dashboard'))
    elif role_name == 'guest':
        return redirect(url_for('guest_dashboard'))
    else:
        return redirect(url_for('dashboard'))

    # user = User.get_by_id(current_user.id)  # Fetch the latest user data
    # if user:
    #     return render_template('dashboard.html', user=user)  # Pass updated user
    # else:
    #     flash('User data not found.', 'danger')
    #     return redirect(url_for('login'))

    #==========Gen and verify token======================
def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt='email-verification')

def verify_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt='email-verification', max_age=expiration)
    except:
        return None
    return email
#===================email verification========================
@app.route('/verify_email/<token>')
def verify_email(token):
    email = verify_token(token)  # Decode the token
    if not email:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('login'))

    # Check if email is already verified
    response = supabase.table('users').select('email_verified').eq('email', email).execute()
    if response.data and response.data[0]['email_verified']:
        flash('Email is already verified. You can log in.', 'info')
        return redirect(url_for('login'))
    
    # ✅ Update email_verified in Supabase
    update_response = supabase.table('users').update({'email_verified': True}).eq('email', email).execute()

    print(f"Email verification update response: {update_response}")  # Debugging log

    # ✅ Fetch updated user data
    user = User.get_by_email(email)
    if user:
        login_user(user, remember=True)  # 🔹 Refresh session properly
        flash('Email verified successfully! You can now log in.', 'success')
        return redirect(url_for('dashboard'))

    flash('Verification successful, but there was an issue loading your profile.', 'warning')
    return redirect(url_for('login'))

#resend verification
@app.route('/resend_verification', methods=['POST'])
def resend_verification():
    email = request.form['email']

    # ✅ Fetch latest user data to ensure email verification status is correct
    user = User.get_by_email(email)
    if user and user.email_verified:
        flash('Your email is already verified. You can log in.', 'info')
        return redirect(url_for('login'))

    if user:
        # Generate a new token and send verification email
        token = generate_verification_token(email)
        verification_url = url_for('verify_email', token=token, _external=True)
        try:
            msg = Message("Verify Your Email", sender="demomindwaveweb@gmail.com", recipients=[email])
            msg.body = f"Click the link to verify your email: {verification_url}"
            mail.send(msg)
            flash('A new verification email has been sent!', 'success')
        except Exception as e:
            flash(f"Failed to send email: {str(e)}", 'danger')
    else:
        flash("No account found with this email.", "danger")

    return redirect(url_for('login'))

#Admin access
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Fetch the role_id for the given role_name
            role_response = supabase.table('roles').select('id').eq('name', role_name).execute()
            if not role_response.data:
                flash('Role not found.', 'danger')
                return redirect(url_for('home'))

            role_id = role_response.data[0]['id']

            # Check if the user has the required role
            if not current_user.is_authenticated or current_user.role_id != role_id:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('home'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/admin')
@login_required
@role_required('admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/user')
@login_required
@role_required('user')
def user_dashboard():
    return render_template('user_dashboard.html')

@app.route('/guest')
@role_required('guest')
def guest_dashboard():
    return render_template('guest_dashboard.html')





@app.route('/user/edit_profile', methods=['GET', 'POST'])
@login_required
@role_required('user')
def edit_profile():
    if request.method == 'POST':
        # Handle form submission to update the user's profile
        name = request.form.get('name')
        email = request.form.get('email')
        # Update the user's profile in the database
        response = supabase.table('users').update({
            'name': name,
            'email': email
        }).eq('id', current_user.id).execute()
        if response.data:
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Failed to update profile. Please try again.', 'danger')
    # Render the edit profile form
    return render_template('edit_profile.html', user=current_user)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user():
    if request.method == 'POST':
        # Handle form submission to add a new user
        username = request.form.get('username')
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role_id = request.form.get('role_id')

        # Hash the password
        password_hash = generate_password_hash(password)

        # Insert the new user into the database
        response = supabase.table('users').insert({
            'username': username,
            'name': name,
            'email': email,
            'password_hash': password_hash,
            'email_verified': False,
            'role_id': role_id
        }).execute()

        if response.data:
            flash('User added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Failed to add user. Please try again.', 'danger')

    # Fetch roles for the dropdown
    roles_response = supabase.table('roles').select('*').execute()
    roles = roles_response.data if roles_response.data else []

    # Render the add user form
    return render_template('add_user.html', roles=roles)

@app.route('/admin/users')
@login_required
@role_required('admin')
def list_users():
    # Fetch all users from the database
    response = supabase.table('users').select('*').execute()
    users = response.data if response.data else []
    return render_template('list_users.html', users=users)

@app.route('/admin/roles', methods=['GET'])
@login_required
@role_required('admin')
def list_roles():
    # Fetch all roles from the database
    response = supabase.table('roles').select('*').execute()
    roles = response.data if response.data else []
    return render_template('list_roles.html', roles=roles)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    if not current_user.has_permission('delete_user'):
        flash('You do not have permission to delete users.', 'danger')
        return redirect(url_for('admin_dashboard'))

    response = supabase.table('users').delete().eq('id', user_id).execute()
    if response.data:
        flash('User deleted successfully!', 'success')
    else:
        flash('Failed to delete user. Please try again.', 'danger')
    return redirect(url_for('list_users'))

@app.route('/user/change_password', methods=['GET', 'POST'])
@login_required
@role_required('user')
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Verify the current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))

        # Check if the new password and confirmation match
        if new_password != confirm_password:
            flash('New password and confirmation do not match.', 'danger')
            return redirect(url_for('change_password'))

        # Hash the new password
        new_password_hash = generate_password_hash(new_password)

        # Update the user's password in the database
        response = supabase.table('users').update({
            'password_hash': new_password_hash
        }).eq('id', current_user.id).execute()

        if response.data:
            flash('Password changed successfully!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Failed to change password. Please try again.', 'danger')

    return render_template('change_password.html')

#======Login Session ==========
@app.route('/sessions')
@login_required
def view_sessions():
    # Fetch active sessions for the current user
    response = supabase.table('user_logins').select('*').eq('userid', current_user.id).is_('logout_timestamp', 'NULL').execute()
    sessions = response.data if response.data else []
    return render_template('sessions.html', sessions=sessions)
@app.route('/logout_all_sessions', methods=['POST'])
@login_required
def logout_all_sessions():
    # Delete all sessions for the current user
    try:
        response = supabase.table('user_logins').delete().eq('userid', current_user.id).execute()
        if response.data:
            flash('Logged out of all sessions successfully!', 'success')
        else:
            flash('No active sessions found.', 'info')
    except Exception as e:
        flash(f"Error logging out of all sessions: {str(e)}", 'danger')

    return redirect(url_for('dashboard'))
@app.route('/logout_session/<int:session_id>', methods=['POST'])
@login_required
def logout_session(session_id):
    try:
        response = supabase.table('user_logins').delete().eq('id', session_id).eq('userid', current_user.id).execute()
        if response.data:
            flash('Session logged out successfully!', 'success')
        else:
            flash('Session not found.', 'info')
    except Exception as e:
        flash(f"Error logging out session: {str(e)}", 'danger')
    return redirect(url_for('view_sessions'))

#login session End=============
#Password reset feature
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt='password-reset')

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt='password-reset', max_age=expiration)
    except:
        return None
    return email
@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'POST':
        email = request.form['email']
        user = User.get_by_email(email)

        if user:
            # Generate a reset token
            token = generate_reset_token(email)
            reset_url = url_for('reset_password', token=token, _external=True)

            # Send reset email
            try:
                msg = Message("Password Reset Request", sender="demomindwaveweb@gmail.com", recipients=[email])
                msg.body = f"Click the link to reset your password: {reset_url}"
                mail.send(msg)
                flash('A password reset link has been sent to your email.', 'success')
            except Exception as e:
                flash(f"Failed to send email: {str(e)}", 'danger')
        else:
            flash("No account found with this email.", "danger")

    return render_template('request_password_reset.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        # Hash the new password using bcrypt
        password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Update the user's password in the database
        response = supabase.table('users').update({
            'password_hash': password_hash
        }).eq('email', email).execute()

        if response.data:
            flash('Your password has been reset successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Failed to reset password. Please try again.', 'danger')

    return render_template('reset_password.html', token=token)

@app.route('/user/delete_account', methods=['GET', 'POST'])
@login_required
@role_required('user')
def delete_account():
    if request.method == 'POST':
        password = request.form.get('password')

        if not current_user.check_password(password):
            flash('Incorrect password. Please try again.', 'danger')
            return redirect(url_for('delete_account'))

        try:
            # Delete user sessions
            supabase.table('user_logins').delete().eq('userid', current_user.id).execute()

            # Remove user from groups
            supabase.table('user_groups').delete().eq('user_id', current_user.id).execute()

            # Delete the user's account
            response = supabase.table('users').delete().eq('id', current_user.id).execute()

            if response.data:
                flash('Your account has been deleted successfully.', 'success')
                logout_user()
                return redirect(url_for('home'))
            else:
                flash('Failed to delete account. Please try again.', 'danger')
        except Exception as e:
            flash(f"Error deleting account: {str(e)}", 'danger')

    return render_template('delete_account.html')


#UPLOAD PROFILE PHOTO
# Upload Profile Picture Route
@app.route('/upload_profile_picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'file' not in request.files:
        print("🚨 No file received in request")
        flash('No file uploaded!', 'danger')
        return redirect(url_for('dashboard'))

    file = request.files['file']

    if file.filename == '' or file.read() == b'':
        print("🚨 Empty file received")
        flash('No file selected!', 'danger')
        return redirect(url_for('dashboard'))

    file.seek(0)  # Reset file cursor

    if not allowed_file(file.filename):
        print(f"🚨 Invalid file type: {file.filename}")
        flash('Invalid file type. Only images are allowed.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Upload to Cloudinary
        upload_result = upload(file, folder="profile_pictures")

        if 'secure_url' not in upload_result:
            flash('Upload failed. Please try again.', 'danger')
            return redirect(url_for('dashboard'))

        image_url = upload_result['secure_url']
        print(f"✅ Uploaded image URL: {image_url}")

        # Update user's profile picture in Supabase
        response = supabase.table('users').update({
            'profile_picture_url': image_url
        }).eq('id', current_user.id).execute()

        print(f"✅ Supabase Response: {response}")

        if response and response.get('data'):
            flash('Profile picture updated successfully!', 'success')
        else:
            flash('Failed to update profile picture in database.', 'danger')

    except Exception as e:
        print(f"🚨 Error: {str(e)}")
        flash(f"Error uploading file: {str(e)}", 'danger')

    return redirect(url_for('dashboard'))

# Helper function to check allowed file extensions
def allowed_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
#---------------------------













# Run Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)