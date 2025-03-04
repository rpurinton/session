#!/usr/bin/env php
<?php

use RPurinton\{Log, MySQL, User};

require_once __DIR__ . '/vendor/autoload.php';
Log::install();
$user = new User(MySQL::connect(), 12345,['username' => 'foo']);
$user->save();
