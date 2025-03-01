#!/usr/bin/env php
<?php

use RPurinton\{Log, MySQL, Session, User};

require_once __DIR__ . '/vendor/autoload.php';
Log::install();
$session = Session::connect(true, true);
echo "Session Data: " . print_r($session);
