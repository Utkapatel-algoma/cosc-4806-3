<?php

class Logout extends Controller {

    public function index() {        
        // session_start();- REMOVED
        $_SESSION = array(); // Cleared twice
        session_destroy();    
        header('location:/login');
        exit; // Added exit - working
    }
}