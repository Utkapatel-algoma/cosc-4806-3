<?php

class App {

    protected $controller = 'login';
    protected $method = 'index';
    protected $special_url = ['apply'];
    protected $params = [];

    public function __construct() {
        if (isset($_SESSION['auth']) == 1) {
            //$this->method = 'index';
            $this->controller = 'home';
        } 

        // This will return a broken up URL
        // it will be /controller/method
        $url = $this->parseUrl();

        /* if controller exists in the URL, then go to it
         * if not, then go to this->controller which is defaulted to home 
         */

        if (file_exists('app/controllers/' . $url[1] . '.php')) {
            $this->controller = $url[1];

            $_SESSION['controller'] = $this->controller;

            /* This is if we have a special URL in the index.
             * For example, our apply page is public and in the index method
             * We do not want the method to be login in this case, but instead index
             * 
             */
            if (in_array($this->controller, $this->special_url)) { 
              $this->method = 'index';
            }
            unset($url[1]);
        } else {
            header('Location: /home');
            die;
        }

        require_once 'app/controllers/' . $this->controller . '.php';

        $this->controller = new $this->controller;

        // check to see if method is passed
        // check to see if it exists
        if (isset($url[2])) {
            if (method_exists($this->controller, $url[2])) {
                $this->method = $url[2];
                $_SESSION['method'] = $this->method;
                unset($url[2]);
            }
        }

        // This will rebase the params to a new array (starting at 0)
        // if params exist
        $this->params = $url ? array_values($url) : [];
        call_user_func_array([$this->controller, $this->method], $this->params);		
    }

    public function parseUrl() {
        $u = "{$_SERVER['REQUEST_URI']}";
        //trims the trailing forward slash (rtrim), sanitizes URL, explode it by forward slash to get elements
        $url = explode('/', filter_var(rtrim($u, '/'), FILTER_SANITIZE_URL));
		unset($url[0]);
		return $url;
    }

}
