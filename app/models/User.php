<?php

class User {

    public $username;
    public $password;
    public $auth = false;

    public function __construct() {

    }

    public function test () {
        $db = db_connect();
        $statement = $db->prepare("select * from users;");
        $statement->execute();
        $rows = $statement->fetch(PDO::FETCH_ASSOC);
        return $rows;
    }

    public function authenticate($username, $password) {
        $username = strtolower($username);

        $db = db_connect();
        $statement = $db->prepare("select * from users WHERE username = :name;");
        $statement->bindValue(':name', $username);
        $statement->execute();
        $rows = $statement->fetch(PDO::FETCH_ASSOC);

        $log_attempt_status = 'bad'; // Default to 'bad' status for the log

        // Check if user exists and password is correct
        if ($rows && password_verify($password, $rows['password'])) {
            $_SESSION['auth'] = 1;
            $_SESSION['username'] = ucwords($username);
            unset($_SESSION['failedAuth']);
            $log_attempt_status = 'good'; // Change status to 'good' on successful login

            // Log the successful login attempt
            $this->logLoginAttempt($username, $log_attempt_status);

            header('Location: /home');
            die; // Important to exit after header redirect
        } else {
            // Increment failed attempt counter
            if(isset($_SESSION['failedAuth'])) {
                $_SESSION['failedAuth']++;
            } else {
                $_SESSION['failedAuth'] = 1;
            }

            // Log the failed login attempt
            $this->logLoginAttempt($username, $log_attempt_status);

            header('Location: /login');
            die; // Important to exit after header redirect
        }
    }

    /**
     * Logs a login attempt to the 'log' table.
     *
     * @param string $username The username involved in the login attempt.
     * @param string $attempt_status 'good' for successful login, 'bad' for failed.
     * @return void
     */
    private function logLoginAttempt($username, $attempt_status) {
        $db = db_connect(); // Get database connection

        // Ensure connection is valid before proceeding
        if ($db) {
            $stmt = $db->prepare("INSERT INTO log (username, attempt, timestamp) VALUES (?, ?, NOW())");
            // Use NOW() for MySQL/MariaDB. If SQLite, CURRENT_TIMESTAMP is typically used.
            // Based on your config, you are using MySQL/MariaDB.

            // Execute the prepared statement with the given values
            if (!$stmt->execute([$username, $attempt_status])) {
                // Optional: You could log this error to a file if logging to DB fails
                // For now, we'll just let it fail silently or add a simple debug output
                // error_log("Failed to log login attempt for user: $username. Status: $attempt_status");
            }
        } else {
            // Optional: Log an error if db_connect fails
            // error_log("Failed to connect to database for logging login attempt.");
        }
    }

    public function create($username, $password) {
        $db = db_connect();
        $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        if ($stmt->fetch()) return false; // Username already exists

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        return $stmt->execute([$username, $hash]);
    }
}