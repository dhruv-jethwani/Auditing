# 🔐 IAM System - User Authentication & Activity Logging

## Overview

Welcome to IAM System! This is a robust Identity and Access Management (IAM) system designed to handle user registration, secure login, and comprehensive activity logging. It features distinct user roles (user and admin) and provides administrators with a detailed log of all user and admin actions, including IP address and device information, enhancing security monitoring. This application serves as a foundational template for any system requiring secure user authentication and an auditable trail of user activities.

## Key Features

* **Secure User Registration & Login:**
    * New user sign-up.
    * Password hashing for secure storage (using Werkzeug.security).
    * User login with session management.
* **Default Admin Account:**
    * A pre-configured admin account for initial setup and management.
    * **Username:** `admin_user`
    * **Password:** `admin_password` (Please change this immediately after first login for security!)
* **Role-Based Access Control:**
    * Differentiates between regular users and administrators.
    * Specific functionalities and views are restricted to admin users.
* **Comprehensive Activity Logging:**
    * Logs every significant action performed by both users and admins.
    * Captures **IP address** of the user.
    * Records **device details** (User-Agent string).
    * Logs the **action performed** (e.g., 'user_login', 'admin_view_logs', 'user_register').
    * Includes a **timestamp** for each log entry.
* **Admin-Exclusive Activity Log View:**
    * A dedicated dashboard/page accessible only to the admin.
    * Displays all recorded user and admin activities in an organized manner.
* **Local Database:** Uses SQLite for easy setup and local data storage during development.

## Technologies Used

* **Backend:**
    * Python 3.x
    * Flask: A lightweight and flexible web framework.
    * Flask-SQLAlchemy: ORM for database interactions.
    * SQLite: A file-based SQL database, ideal for local development and testing.
    * Werkzeug.security: Used for secure password hashing (highly recommended for production).
    * `request` object (Flask): Used to capture IP and User-Agent details for logging.
* **Frontend:**
    * HTML5: Structure of the web pages.
    * CSS3: Styling for a clean and intuitive user interface.
    * JavaScript: (For client-side interactions, e.g., form validation, if implemented).

## Getting Started

Follow these instructions to set up and run the project locally.

### Prerequisites

* Python 3.x installed on your system.
* `pip` (Python package installer)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git](https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git)
    cd YOUR_REPO_NAME # Navigate into your project directory
    ```
    *(Replace `YOUR_USERNAME` and `YOUR_REPO_NAME` with your actual GitHub details, e.g., `cd iam-app`)*

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    ```


3.  **Install the required Python packages:**
    ```bash
    pip install Flask Flask-SQLAlchemy Werkzeug
    # Add any other libraries you might have installed (e.g., Flask-Login if used)
    ```
    
### Default Admin Account

For initial access and setup, use the following credentials:

* **Username:** `admin_user`
* **Password:** `admin_password`

**SECURITY WARNING:** It is strongly recommended to **change the password** for the `admin_user` immediately after your first successful login.

## Database Management

This project uses SQLite for its database.

* The database file (`database.db` by default) will be created inside the `instance/` folder in your project's root directory when you first run the application (specifically, when `db.create_all()` is executed).
* **To reset the database (for development):**
    1.  Deactivate your virtual environment (`deactivate`).
    2.  Delete the `instance/` folder (or just `instance/database.db`).
    3.  Reactivate your virtual environment and run the application again (`flask run`). This will create a fresh, empty database.
