#!/usr/bin/env php
<?php

use RPurinton\{Log, MySQL, User};

require_once __DIR__ . '/vendor/autoload.php';
Log::install();
$user = User::get(MySQL::connect(), 12345);
if ($user) die("Success! " . print_r($user, true));
echo ("Failure?!... Expected a user but got null :(\n");
