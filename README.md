# Vault Guardian: Next.js Secure Password Vault
Vault Guardian is a minimal, privacy-focused web application designed to securely generate, store, and manage user credentials. The core principle of the application is Client-Side Encryption, ensuring that the server (MongoDB) only ever stores encrypted data blobs.



# Tech Stack
Frontend: Next.js (TypeScript) & React
Styling: Tailwind CSS
Backend: Next.js API Routes (TypeScript)
Database: MongoDB
Authentication: JSON Web Tokens (JWT)
Cryptography: crypto-js (Client-Side AES Encryption)



# 🔒 Cryptography Note
We use the crypto-js library for all client-side encryption. This library provides robust AES-256 encryption. Crucially, the user's Master Password is never stored or sent to the server directly. Instead, it is used to derive a powerful, unique encryption key using PBKDF2 (Password-Based Key Derivation Function 2). This derived key then encrypts the entire vault item structure before it leaves the browser, guaranteeing that only the user, possessing the original master password, can ever decrypt their data.


# ⚙️ How to Run Locally
Follow these steps to set up the project on your local machine.
1. Installation
First, ensure you have Node.js and npm installed. Navigate to the project root directory in your terminal and install all dependencies:
npm install
2. Environment Setup (Necessary)
You must configure your environment variables for the database and security keys. Create a file named .env.local in the project root directory and add the following variables.
IMPORTANT: Replace the placeholders with your actual, long, random secret values.



# 1. MongoDB Connection String (Required for database access)
MONGODB_URI="mongodb+srv://<USERNAME>:<PASSWORD>@cluster0.k9cjp8z.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
# 2. JWT Secret Key (Used on the server to sign/verify authentication tokens)
# Use a strong, random, 64-byte Base64 string.
JWT_SECRET="PASTE_YOUR_STRONG_RANDOM_JWT_SECRET_HERE" 
# 3. Encryption Salt (Used on the client for PBKDF2 key derivation)
# Use a strong, random, 64-byte Base64 string.
ENCRYPTION_SALT="PASTE_YOUR_STRONG_RANDOM_ENCRYPTION_SALT_HERE"



# 3. Start the Application
Once the dependencies and environment variables are set, start the Next.js development server:
npm run dev
The application will now be accessible at http://localhost:3000.



# Key Features
Client-Side Encryption: Vault data is only ever stored as ciphertext on the server.
Password Generator: Highly configurable length and character set options.
Secure Session: JWT-based authentication for user sessions.
CRUD Operations: Ability to View, Edit, and Delete saved vault entries.
Instant Search: Client-side filtering of decrypted vault items.
Clipboard Auto-Clear: Passwords copied to the clipboard are automatically cleared after 15 seconds for security.
