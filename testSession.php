#!/usr/bin/env php
<?php

use RPurinton\{Log, MySQL, Session, User};

require_once __DIR__ . '/vendor/autoload.php';

$session = new Session("example.com", true, true);
echo "Session Data: " . print_r($session);

