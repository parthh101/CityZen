from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from jose import JWTError, jwt
from functools import wraps

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Security configuration
SECRET_KEY = "your-secret-key-here"  # In production, use a secure secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database connection
def get_db():
    try:
        conn = psycopg2.connect(
            host="localhost",
            database="CityZen",
            user="postgres",
            password="1234",
            cursor_factory=RealDictCursor
        )
        return conn
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            current_user = data['sub']
        except JWTError:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Routes
@app.route('/')
def root():
    return jsonify({"message": "Welcome to CityZen API"})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    required_fields = ['full_name', 'email', 'password', 
                      'phone_number', 'address', 'city', 'state']
    
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    try:
        conn = get_db()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        
        # Check if email already exists
        cursor.execute("SELECT email FROM users WHERE email = %s", (data['email'],))
        if cursor.fetchone():
            return jsonify({"error": "Email already registered"}), 400
            
        cursor.execute(
            """
            INSERT INTO users (full_name, email, password, phone_number, address, city, state)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING user_id
            """,
            (
                data['full_name'], data['email'], data['password'],
                data['phone_number'], data['address'], data['city'], data['state']
            )
        )
        user_id = cursor.fetchone()['user_id']
        conn.commit()
        
        # Create access token
        access_token = create_access_token(
            data={"sub": str(user_id)},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        return jsonify({
            "message": "User registered successfully",
            "user_id": user_id,
            "access_token": access_token
        })
    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": str(e)}), 400
    finally:
        if conn:
            conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({"error": "Email and password are required"}), 400

    try:
        conn = get_db()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE email = %s AND password = %s",
            (data['email'], data['password'])
        )
        user_data = cursor.fetchone()
        
        if not user_data:
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Create access token
        access_token = create_access_token(
            data={"sub": str(user_data['user_id'])},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        # Remove password from response
        user_data.pop('password', None)
        
        return jsonify({
            "message": "Login successful",
            "user": user_data,
            "access_token": access_token
        })
    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": str(e)}), 400
    finally:
        if conn:
            conn.close()

@app.route('/api/logout', methods=['POST'])
def logout():
    data = request.get_json()
    if not data or 'user_id' not in data:
        return jsonify({"error": "User ID is required"}), 400

    try:
        conn = get_db()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET is_logged_in = FALSE WHERE user_id = %s",
            (data['user_id'],)
        )
        conn.commit()
        return jsonify({"message": "Logout successful"})
    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": str(e)}), 400
    finally:
        if conn:
            conn.close()

@app.route('/api/profile/update', methods=['POST'])
@token_required
def update_profile(current_user):
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    try:
        conn = get_db()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        
        # Build the update query dynamically based on provided fields
        update_fields = []
        update_values = []
        
        # List of allowed fields that can be updated
        allowed_fields = ['full_name', 'email', 'phone_number', 'address', 'city', 'state']
        
        for field in allowed_fields:
            if field in data:
                update_fields.append(f"{field} = %s")
                update_values.append(data[field])
        
        if not update_fields:
            return jsonify({"error": "No valid fields to update"}), 400
            
        # Add user_id to the values list
        update_values.append(current_user)
        
        # Construct and execute the update query
        update_query = f"""
            UPDATE users 
            SET {', '.join(update_fields)}
            WHERE user_id = %s
            RETURNING *
        """
        
        cursor.execute(update_query, update_values)
        updated_user = cursor.fetchone()
        conn.commit()
        
        if not updated_user:
            return jsonify({"error": "User not found"}), 404
            
        # Remove password from response
        updated_user.pop('password', None)
            
        return jsonify({
            "message": "Profile updated successfully",
            "user": updated_user
        })
        
    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({"error": str(e)}), 400
    finally:
        if conn:
            conn.close()

@app.route('/api/debug/users', methods=['GET'])
def list_users():
    try:
        conn = get_db()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        return jsonify({"users": users})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        if conn:
            conn.close()

@app.route('/api/feedback/submit', methods=['POST'])
def submit_feedback():
    print("Feedback submission started")  # Debug log
    data = request.get_json()
    print(f"Received data: {data}")  # Debug log
    
    if not data:
        print("No data received")  # Debug log
        return jsonify({"error": "No data received"}), 400
        
    if 'user_id' not in data:
        print("user_id missing")  # Debug log
        return jsonify({"error": "user_id is required"}), 400
        
    if 'subject' not in data:
        print("subject missing")  # Debug log
        return jsonify({"error": "subject is required"}), 400
        
    if 'message' not in data:
        print("message missing")  # Debug log
        return jsonify({"error": "message is required"}), 400

    try:
        print("Attempting database connection")  # Debug log
        conn = get_db()
        if not conn:
            print("Database connection failed")  # Debug log
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        print(f"Checking for user_id: {data['user_id']}")  # Debug log
        
        # First check if user exists with more detailed logging
        cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (data['user_id'],))
        user = cursor.fetchone()
        print(f"User query result: {user}")  # Debug log
        
        if not user:
            print(f"No user found with ID: {data['user_id']}")  # Debug log
            return jsonify({
                "error": "User not found",
                "details": f"No user found with ID: {data['user_id']}",
                "received_data": data
            }), 404

        print("Attempting to insert feedback")  # Debug log
        # Insert feedback
        cursor.execute(
            """
            INSERT INTO feedback (user_id, subject, message)
            VALUES (%s, %s, %s)
            RETURNING feedback_id
            """,
            (data['user_id'], data['subject'], data['message'])
        )
        feedback_id = cursor.fetchone()['feedback_id']
        print(f"Feedback inserted with ID: {feedback_id}")  # Debug log
        conn.commit()
        
        return jsonify({
            "message": "Feedback submitted successfully",
            "feedback_id": feedback_id
        })
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")  # Debug log
        if conn:
            conn.rollback()
        return jsonify({
            "error": str(e),
            "details": "An error occurred while processing your feedback",
            "received_data": data
        }), 400
    finally:
        if conn:
            conn.close()
            print("Database connection closed")  # Debug log

@app.route('/api/debug/feedback', methods=['GET'])
def list_feedback():
    try:
        conn = get_db()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        cursor.execute("""
            SELECT f.*, u.full_name, u.email 
            FROM feedback f
            JOIN users u ON f.user_id = u.user_id
            ORDER BY f.created_at DESC
        """)
        feedback = cursor.fetchall()
        return jsonify({"feedback": feedback})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        if conn:
            conn.close()

@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    print(f"Getting profile for user_id: {current_user}")  # Debug log
    try:
        conn = get_db()
        if not conn:
            print("Database connection failed")  # Debug log
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        query = """
            SELECT user_id, full_name, email, phone_number, address, city, state 
            FROM users 
            WHERE user_id = %s
        """
        print(f"Executing query: {query} with user_id: {current_user}")  # Debug log
        
        cursor.execute(query, (current_user,))
        user_data = cursor.fetchone()
        print(f"Query result: {user_data}")  # Debug log
        
        if not user_data:
            print(f"No user found with ID: {current_user}")  # Debug log
            return jsonify({"error": "User not found"}), 404
            
        print(f"Returning user data: {user_data}")  # Debug log
        return jsonify(user_data)
    except Exception as e:
        print(f"Error in get_profile: {str(e)}")  # Debug log
        return jsonify({"error": str(e)}), 400
    finally:
        if conn:
            conn.close()
            print("Database connection closed")  # Debug log

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8000) 