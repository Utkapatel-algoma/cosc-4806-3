<?php
class Create extends Controller {
    public function index() {
        $this->view('create/index');
    }

    public function register() {
        $user = new User();

        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';

        if ($user->create($username, $password)) {
            $_SESSION['message'] = "Account created. Please login.";
            header('Location: /login');
        } else {
            $_SESSION['error'] = "Username may already exist.";
            header('Location: /create');
        }
    }
}