import os
import uuid
import datetime
import logging
import boto3
from boto3.dynamodb.conditions import Key
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, Blueprint
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = Flask(__name__)
app.secret_key = os.urandom(24)

# Blueprints
auth_bp = Blueprint('auth', __name__)
booking_bp = Blueprint('booking', __name__)

# AWS Services
def get_dynamodb():
    if 'dynamodb' not in g:
        g.dynamodb = boto3.resource('dynamodb', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
    return g.dynamodb

def get_sns():
    if 'sns' not in g:
        g.sns = boto3.client('sns', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
    return g.sns

# DynamoDB Tables
def get_users_table():
    return get_dynamodb().Table('SalonUsers')

def get_appointments_table():
    return get_dynamodb().Table('SalonAppointments')

def get_stylists_table():
    return get_dynamodb().Table('SalonStylists')

# SNS Topic ARN
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')

# Email settings
SMTP_EMAIL = os.environ.get('SMTP_EMAIL')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
SMTP_SERVER = os.environ.get('SMTP_SERVER')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))

# Helper Functions
def send_email(to_email, subject, body):
    try:
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        import smtplib

        msg = MIMEMultipart()
        msg['From'] = SMTP_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        logger.info(f"Email sent to {to_email}")
    except Exception as e:
        logger.error(f"Error sending email: {e}")

def send_sns_notification(message):
    try:
        get_sns().publish(TopicArn=SNS_TOPIC_ARN, Message=message)
        logger.info("SNS notification sent")
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {e}")

def get_stylists():
    try:
        return get_stylists_table().scan().get('Items', [])
    except Exception as e:
        logger.error(f"Error fetching stylists: {e}")
        return []

def get_user_by_email(email):
    try:
        response = get_users_table().get_item(Key={'email': email})
        return response.get('Item')
    except Exception as e:
        logger.error(f"Error fetching user by email: {e}")
        return None

import uuid  # Put at the top of your file if not already imported

def create_user(name, email, phone, password):
    try:
        table = get_users_table()
        user_id = str(uuid.uuid4())  # ✅ generate unique user_id

        response = table.put_item(Item={
            'user_id': user_id,
            'email': email,
            'name': name,
            'phone': phone,
            'password': generate_password_hash(password),
            'created_at': str(datetime.datetime.utcnow())
        })

        return True
    except Exception as e:
        print("❌ Error creating user:", repr(e))
        traceback.print_exc()
        return False


# Authentication Routes (Blueprint)
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user_by_email(email)

        if user and check_password_hash(user['password'], password):
            # ✅ Corrected key name from 'id' to 'user_id'
            session['user_id'] = user.get('user_id', user.get('email'))  # fallback to email if user_id is missing
            session['user_name'] = user.get('name', 'User')
            session['user_email'] = user.get('email')
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            error = "Invalid email or password"

    return render_template('login.html', error=error)



@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            error = "Passwords do not match"
        elif len(password) < 6:
            error = "Password must be at least 6 characters"
        else:
            # Check if the email already exists in DynamoDB
            if get_user_by_email(email):
                error = "Email already exists"
            elif create_user(name, email, phone, password):
                flash('Account created! Please login.', 'success')
                return redirect(url_for('auth.login'))
            else:
                error = "Failed to create account"
    return render_template('signup.html', error=error)

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('auth.login'))

# Booking Routes (Blueprint)
@booking_bp.route('/', methods=['GET', 'POST'])
def booking():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    error, success = None, None
    stylists = get_stylists()

    if request.method == 'POST':
        service = request.form['service']
        stylist_id = request.form['stylist']
        date_str = request.form['date']
        time_str = request.form['time']
        notes = request.form['notes']

        try:
            # Convert date and time from form data
            appointment_date = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
            appointment_time = datetime.datetime.strptime(time_str, '%H:%M').time()
            today = datetime.date.today()

            if appointment_date < today:
                error = "Appointment date cannot be in the past"
            else:
                # Check if the time slot is available for the stylist
                response = get_appointments_table().scan(FilterExpression=Key('stylist_id').eq(stylist_id))
                for appt in response['Items']:
                    if appt['appointment_date'] == date_str and appt['appointment_time'] == time_str and appt['status'] == 'scheduled':
                        error = "This time slot is already booked"
                        break
                else:
                    # ✅ Generate a unique appointment_id using current timestamp
                    appointment_id = str(datetime.datetime.utcnow().timestamp()).replace('.', '')  # Partition Key
                    user_email = session.get('user_email')  # Assuming the user_email is stored in the session

                    # ✅ Create the appointment item for DynamoDB
                    appointment_item = {
                        'appointment_id': appointment_id,   # Partition Key
                        'user_email': user_email,           # Sort Key
                        'user_id': session['user_id'],
                        'stylist_id': stylist_id,
                        'service': service,
                        'appointment_date': date_str,
                        'appointment_time': time_str,
                        'notes': notes,
                        'status': 'scheduled',
                        'created_at': str(datetime.datetime.utcnow())
                    }

                    print("📦 Appointment to Insert:", appointment_item)  # Debugging step

                    # ✅ Put item in DynamoDB
                    try:
                        get_appointments_table().put_item(Item=appointment_item)
                    except Exception as e:
                        error = f"Error inserting into DynamoDB: {e}"
                        print("⚠️ DynamoDB Error:", e)
                        return render_template('booking.html', error=error, success=success, stylists=stylists)

                    # Send notifications
                    message = f"Appointment booked for {session['user_name']} with stylist ID {stylist_id} on {date_str} at {time_str}."
                    send_sns_notification(message)
                    send_email("client@example.com", "Salon Appointment Confirmed", message)

                    success = "Your appointment has been booked successfully!"

        except ValueError as e:
            error = f"Invalid date or time format: {e}"
        except Exception as e:
            error = f"Error booking appointment: {e}"

    return render_template(
        'booking.html',
        error=error,
        success=success,
        stylists=stylists,
        min_date=datetime.date.today().strftime('%Y-%m-%d')
    )

@booking_bp.route('/appointments')
def appointments():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    # Instead of scanning for user_id, scan using 'user_email' or similar field
    response = get_appointments_table().scan(FilterExpression=Key('user_email').eq(session['user_email']))
    appointments = response['Items']

    stylists_map = {stylist['id']: stylist['name'] for stylist in get_stylists()}
    for appt in appointments:
        appt['stylist_name'] = stylists_map.get(appt['stylist_id'], "Unknown")

    return render_template('appointments.html', appointments=appointments)


@booking_bp.route('/cancel/<string:appointment_id>')
def cancel_appointment(appointment_id):
    #... (cancel appointment logic)
    pass
@booking_bp.route('/reschedule/<string:appointment_id>', methods = ['GET','POST'])
def reschedule_appointment(appointment_id):
    #... (reschedule appointment logic)
    pass

# Main Routes
@app.route('/')
def index():
    return redirect(url_for('home')) if 'user_id' in session else redirect(url_for('auth.login'))

@app.route('/home')
def home():
    return render_template('home.html', user_name=session.get('user_name')) if 'user_id' in session else redirect(url_for('auth.login'))

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(booking_bp, url_prefix='/booking')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
