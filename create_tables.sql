-- Create users table
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    date_of_birth DATE NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    address TEXT NOT NULL,
    city VARCHAR(50) NOT NULL,
    state VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_logged_in BOOLEAN DEFAULT FALSE
);

-- Create feedback table
CREATE TABLE IF NOT EXISTS feedback (
    feedback_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    subject VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
); 