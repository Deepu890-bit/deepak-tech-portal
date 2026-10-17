# Deepak Technologies — Authentication & Enterprise Portal

A secure, full-stack web application featuring user registration, credential authentication, session tokens, and a multi-view cinematic interface built with Node.js, Express, and MySQL.

## Key Features

* **Secure Authentication**: Passwords hashed with `bcryptjs` using a salt round of 10 before database storage.
* **JWT Session Management**: 24-hour signed JSON Web Tokens for persistent browser sessions.
* **Brute-Force Protection**: IP rate limiting via `express-rate-limit` to prevent credential-stuffing attacks.
* **SQL Injection Prevention**: Parameterized queries using the `mysql2/promise` connection pool.
* **Cinematic Interface**: Pure HTML5 and CSS3 single-page architecture with deep red-and-black styling, glassmorphism, and responsive navigation.

## Tech Stack

* **Frontend**: HTML5, CSS3, Vanilla JavaScript (Fetch API, LocalStorage)
* **Backend**: Node.js, Express.js
* **Database**: MySQL (configured via MySQL Workbench)
* **Security & Auth**: `bcryptjs`, `jsonwebtoken`, `express-rate-limit`, `dotenv`

## Project Structure

```text
emailwork/
├── public/
│   ├── index.html        # Single-page UI (Home, About, Contact, Auth)
│   └── deepak.jpg        # Founder profile photo
├── .env                  # Environment variables (ignored by Git)
├── .env.example          # Template for environment variables
├── .gitignore            # Git exclusion rules
├── db.js                 # MySQL connection pool configuration
├── package.json          # Node dependencies and scripts
├── README.md             # Project documentation
└── server.js             # Express application and API endpoints
