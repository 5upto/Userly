# Userly (User Management System)

A full-stack user management system built with React and Node.js. This application provides a complete solution for user authentication, registration, and management.

## Features

- User Authentication (Login/Register)
- Dashboard with user information
- Modern UI with React components
- API Rate Limiting
- JWT Token-based Authentication
- Secure Password Hashing
- Responsive Design

## Tech Stack

### Frontend
- React 19.1.0
- Vite (Build Tool)
- TailwindCSS 4.1.11
- React Router DOM 7.7.1
- Axios for API calls
- React Toastify for notifications

### Backend
- Node.js
- Express.js 4.18.2
- MySQL 2
- JWT Authentication
- bcryptjs for password hashing
- CORS Middleware
- Express Rate Limiter
- dotenv for environment variables

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- MySQL Server
- npm or yarn

### Installation

1. Clone the repository
2. Install dependencies for both frontend and backend

```bash
cd frontend
npm install
cd ../backend
npm install
```

### Environment Setup

Create a `.env` file in the backend directory with the following variables:

```
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=user_management
PORT=5000
JWT_SECRET=your_jwt_secret
RATE_LIMIT_WINDOW_MS=15000
RATE_LIMIT_MAX_REQUESTS=100
```

### Running the Application

1. Start the backend server:

```bash
cd backend
node server.js
```

2. In a new terminal, start the frontend:

```bash
cd frontend
npm run dev
```

## Project Structure

```
user-management/
├── backend/
│   ├── config/
│   │   └── db.js
│   ├── middleware/
│   │   └── auth.js
│   ├── routes/
│   │   ├── auth.js
│   │   └── users.js
│   ├── .env
│   ├── server.js
│   └── package.json
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Login.jsx
│   │   │   ├── Register.jsx
│   │   │   ├── Dashboard.jsx
│   │   │   └── Toolbar.jsx
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── index.html
│   └── package.json
└── screenshots/
```

## Frontend Components

- `Login.jsx`: Handles user authentication
- `Register.jsx`: Manages user registration
- `Dashboard.jsx`: Displays user information and controls
- `Toolbar.jsx`: Navigation and UI controls

## Backend Features

- Express.js server with REST API endpoints
- MySQL database integration
- JWT authentication
- Rate limiting to prevent abuse
- CORS configuration
- Environment variable support
- Password hashing
- Secure API endpoints

## Security Features

- Password hashing using bcryptjs
- JWT-based authentication
- Rate limiting to prevent API abuse
- CORS configuration for secure API access
- Environment variables for sensitive data

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Screenshots

### Login Page
![Login Page](screenshots/Screenshot%20%28294%29.png)

The login page provides a clean and secure interface for users to access their accounts.

### Registration Page
![Registration Page](screenshots/Screenshot%20%28295%29.png)

The registration page allows new users to create their accounts with essential information.

### Dashboard
![Dashboard](screenshots/Screenshot%20%28296%29.png)

The main dashboard displays user information and provides access to various features.

### Toolbar
![Toolbar](screenshots/Screenshot%20%28297%29.png)

The navigation toolbar offers quick access to different sections of the application.

### User Profile
![User Profile](screenshots/Screenshot%20%28298%29.png)

The user profile section allows users to manage their account settings and preferences.

## Support

For support, please open an issue in the repository or contact the project maintainers.

## Acknowledgments

- Thanks to all contributors who have helped improve this project
- Special thanks to the maintainers of the libraries and tools used in this project
