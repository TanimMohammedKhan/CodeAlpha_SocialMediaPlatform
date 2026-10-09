# Pulse - Mini Social Media Platform

A modern, full-stack mini social networking platform built with **Node.js**, **Express.js**, **SQLite**, and **Tailwind CSS**.

---

## 🚀 Features

- **Authentication & Security:** Secure user registration (Username, Email, Password) and JWT-based authentication with bcrypt password hashing.
- **Dedicated Interfaces:**
  - **News Feed View:** Global stream vs. personalized Following feed with real-time post creation.
  - **Profile View:** Dedicated profile page showcasing user bio, custom avatar upload, follower/following metrics, and personal timeline posts.
- **Social Interactivity:**
  - Dynamic like and unlike toggling.
  - Real-time post comments and threaded discussions.
  - Follow and unfollow creators with interactive follower/following modals.
- **Live User Discovery:** Instant search bar to search and navigate to user profiles.
- **Custom Profile Pictures:** Direct local image file upload support.

---

## 🛠️ Tech Stack

- **Backend:** Node.js, Express.js (v5)
- **Database:** SQLite3 (relational tables for users, posts, comments, likes, follows)
- **Authentication:** JSON Web Tokens (`jsonwebtoken`) & `bcryptjs`
- **Frontend:** Vanilla HTML5, CSS3, JavaScript (ES6+), Tailwind CSS, FontAwesome

---

## ⚙️ Local Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/](https://github.com/)<YOUR_GITHUB_USERNAME>/CodeAlpha_SocialMediaPlatform.git
   cd CodeAlpha_SocialMediaPlatform

   Install dependencies: npm install

   Configure Environment:
Create a .env file in the root directory:
PORT=5000
JWT_SECRET=super_secret_jwt_key_2026

Start the application:node server.js

Open in browser:
Navigate to http://localhost:5000