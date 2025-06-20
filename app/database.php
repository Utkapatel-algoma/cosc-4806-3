<?php

/* database connection stuff here
 * 
 */

function db_connect() {
    try { 
        $dbh = new PDO('mysql:host=' . DB_HOST . ';port='. DB_PORT . ';dbname=' . DB_DATABASE, DB_USER, DB_PASS);
        return $dbh;
    } catch (PDOException $e) {
        //final check
    }
}