import bcrypt

# Define the plain text password as a bytes object
password = b"password123"

# Generate a salted hash of the password using bcrypt
# bcrypt.gensalt() automatically generates a salt with default cost factor
hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

# Print the hashed password as a UTF-8 encoded string
print(hashed_password.decode('utf-8'))
