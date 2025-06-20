<?php

class Login extends Controller {

		public function index() {        
				$this->view('login/index');
		}

		public function verify(){
				// Getting credentials
				$username = $_REQUEST['username'];
				$password = $_REQUEST['password'];

				// starting user modell
				$user = $this->model('User');

				// Authenticating
				// confirm success and failure
				$user->authenticate($username, $password); 
		}

}