#!/usr/bin/env php
<?php

use RPurinton\{Log, MySQL, User};

require_once __DIR__ . '/vendor/autoload.php';
Log::install();
$sql = MySQL::connect();
$username = 'rpurinton';
$password_hash = '5772527c5398c3b1d9999c5a9388823c454126d8a387a32ce461ad7cfc13f656';
$user = User::authenticate($sql, $username, $password_hash);
if ($user) die("Success! " . print_r($user, true));
echo ("Failure?!... Expected a user but got null :(\n");
