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

        //Step 8 started
        $lockout_duration_seconds = 60; // 60 seconds lockout - working
        $max_failed_attempts = 3;    // Max attempts before lockout - working on site aswell


        $recent_attempts_window_seconds = 300; // 5 minutes (300 seconds)
        $stmt = $db->prepare("SELECT COUNT(*) as failed_count, MAX(timestamp) as last_attempt_time FROM log WHERE username = ? AND attempt = 'bad' AND timestamp > (NOW() - INTERVAL ? SECOND)");
        $stmt->execute([$username, $recent_attempts_window_seconds]);
        $failed_log_data = $stmt->fetch(PDO::FETCH_ASSOC);

        $failed_count = $failed_log_data['failed_count'];
        $last_attempt_time = $failed_log_data['last_attempt_time']; 

        if ($failed_count >= $max_failed_attempts) {
            // Converted
            $last_attempt_timestamp = strtotime($last_attempt_time);
            $current_timestamp = time();

            // Calculating remaining time
            $time_elapsed_since_last_fail = $current_timestamp - $last_attempt_timestamp;
            $time_remaining_in_lockout = $lockout_duration_seconds - $time_elapsed_since_last_fail;

            if ($time_remaining_in_lockout > 0) {
                // User is locked out
                $_SESSION['error'] = "Too many failed attempts. Please try again in " . $time_remaining_in_lockout . " seconds.";
                $this->logLoginAttempt($username, 'locked_out'); // Log 'locked_out' status
                header('Location: /login');
                die;
            }
        }
        //step 8 tested and working


        $statement = $db->prepare("select * from users WHERE username = :name;");
        $statement->bindValue(':name', $username);
        $statement->execute();
        $rows = $statement->fetch(PDO::FETCH_ASSOC);

        $log_attempt_status = 'bad'; // Defaulted to 'bad'

        // Checked twice
        if ($rows && password_verify($password, $rows['password'])) {
            $_SESSION['auth'] = 1;
            $_SESSION['username'] = ucwords($username);
            unset($_SESSION['failedAuth']);
            $log_attempt_status = 'good'; // Change status to 'good' on successful login

            // Logging the attempt
            $this->logLoginAttempt($username, $log_attempt_status);

            
            if(isset($_SESSION['failedAuth'])) {
                unset($_SESSION['failedAuth']);
            }

            header('Location: /home');
            die; // exit necessary
        } else {

            if(isset($_SESSION['failedAuth'])) {
                $_SESSION['failedAuth']++;
            } else {
                $_SESSION['failedAuth'] = 1;
            }

            // Logged attempt
            $this->logLoginAttempt($username, $log_attempt_status);

            header('Location: /login');
            die; // exit imporatnt
        }
    }


    private function logLoginAttempt($username, $attempt_status) {
        $db = db_connect(); // Get database connection

        if ($db) {
            $stmt = $db->prepare("INSERT INTO log (username, attempt, timestamp) VALUES (?, ?, NOW())");
            if (!$stmt->execute([$username, $attempt_status])) {

            }
        }
    }

    public function create($username, $password) {
        $db = db_connect();
        $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        if ($stmt->fetch()) return false;

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        return $stmt->execute([$username, $hash]);
    }
}