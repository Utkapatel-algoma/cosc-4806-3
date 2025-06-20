<?php
class Create extends Controller {
    public function index() {
        $this->view('create/index');
    }

    public function register() {
        // changes made to adjust consistencey
        $user = $this->model('User'); // Changed from new User();

        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';

        // Call the model's create method - done
        if ($user->create($username, $password)) {
            $_SESSION['message'] = "Account created. Please login.";
            header('Location: /login');
            exit; // Added exit - changed
        } else {
            $_SESSION['error'] = "Username may already exist.";
            header('Location: /create');
            exit; // Added exit - changed again
        }
    }
}