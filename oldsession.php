<?php

namespace RPurinton\Discommand;

class Session implements \SessionHandlerInterface
{

    public $date = null;
    public $ip_id = null;
    public $ip = array();
    public $name = null;
    public $id = null;
    public $session = array();
    public $user_id = null;
    public $user = array();
    public $loggedin = false;
    public $valid = false;
    public $sql = null;

    public function __construct()
    {
        require_once(__DIR__ . "/SessionSqlClient.php");
        $this->sql = new SessionSqlClient("discommand");
        session_set_save_handler(
            $this->open(...),
            $this->close(...),
            $this->read(...),
            $this->write(...),
            $this->destroy(...),
            $this->gc(...)
        );
        register_shutdown_function('session_write_close');
        $this->name = session_name("discommand");
        session_set_cookie_params(99999999, "/", "discommand.com");
        session_start();
        $this->date = date("Y-m-d");
        $this->refresh();
        return $this;
    }

    public function refresh()
    {
        $this->user_id = $this->get_user_id();
        $this->ip_id = $this->get_ip_id();
        $this->id = $this->get_id();
        $this->audit();
        $url = $_SERVER["HTTP_HOST"] . $_SERVER["REQUEST_URI"];
        if (strpos($url, "login") === false && strpos($url, "logout") === false) {
            if (!$this->loggedin) $this->redirect("https://login.discommand.com/");
            else $this->validate();
        }
    }

    public function open(string $path, string $name): bool
    {
        return true;
    }

    public function read(string $id): string|false
    {
        $result = $this->sql->query("SELECT `data` FROM `sessions_php` WHERE `id` = '$id' LIMIT 0,1");
        if ($this->sql->count($result)) {
            return $this->sql->assoc($result)["data"];
        }
        return "";
    }

    public function write(string $id, string $data): bool
    {
        $access = time();
        if ($this->sql->query("REPLACE INTO `sessions_php` (`id`,`access`,`data`) VALUES ('$id','$access', '$data')")) {
            return true;
        }
        return false;
    }

    public function destroy(string $id): bool
    {
        if ($this->sql->query("DELETE FROM `sessions_php` WHERE `id` = '$id'")) {
            return true;
        }
        return false;
    }

    public function close(): bool
    {
        return true;
    }

    public function gc(int $max_lifetime): int|false
    {
        $stale = time() - $max_lifetime;
        if ($this->sql->query("DELETE FROM `sessions_php` WHERE `access` < '$stale'")) {
            return true;
        }
        return false;
    }

    public function generate_token()
    {
        $chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $result = "";
        while (strlen($result) < 128) {
            $result .= $chars[rand(0, 61)];
        }
        return $result;
    }

    private function get_ip_id()
    {
        if (!isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
            $this->sql->query("UPDATE `ip` SET `views` = `views` + 1 WHERE `id` = 0");
            $this->ip = $this->sql->single("SELECT * FROM `ip` WHERE `id` = 0");
            $this->sql->query("INSERT INTO `ip_history` (`ip_id`,`date`) VALUES ('0','{$this->date}') ON DUPLICATE KEY UPDATE `views` = `views` + 1");
            return 0;
        }
        $ip = $_SERVER["HTTP_CF_CONNECTING_IP"];

        $lat = 0;
        if (isset($_SERVER["HTTP_CF_IPLONGITUDE"])) $lat = $_SERVER["HTTP_CF_IPLONGITUDE"];

        $lon = 0;
        if (isset($_SERVER["HTTP_CF_IPLATITUDE"])) $lon = $_SERVER["HTTP_CF_IPLATITUDE"];

        $city = "";
        if (isset($_SERVER["HTTP_CF_IPCITY"])) $city = $_SERVER["HTTP_CF_IPCITY"];

        $country = "";
        if (isset($_SERVER["HTTP_CF_IPCOUNTRY"])) $country = $_SERVER["HTTP_CF_IPCOUNTRY"];

        $region = "";
        if (isset($_SERVER["HTTP_CF_IPCONTINENT"])) $region = $_SERVER["HTTP_CF_IPCONTINENT"];

        $language = "";
        if (isset($_SERVER["HTTP_ACCEPT_LANGUAGE"])) $language = $this->sql->escape($_SERVER["HTTP_ACCEPT_LANGUAGE"]);

        $user_agent = "";
        if (isset($_SERVER["HTTP_USER_AGENT"])) $user_agent = $this->sql->escape($_SERVER["HTTP_USER_AGENT"]);

        $this->sql->query("INSERT INTO `ip` (`ip`,`last_user_id`,`lat`,`lon`,`city`,`country`,`region`,`language`,`user_agent`)
		VALUES ('$ip','{$this->user_id}','$lat','$lon','$city','$country','$region','$language','$user_agent')
		ON DUPLICATE KEY UPDATE `id` = LAST_INSERT_ID(`id`),
		`last_user_id` = '{$this->user_id}',
		`lat` = '$lat',
		`lon` = '$lon',
		`city` = '$city',
		`country` = '$country',
		`region` = '$region',
		`language` = '$language',
		`user_agent` = '$user_agent',
		`views` = `views`+1");
        $insert_id = $this->sql->insert_id();
        $this->ip = $this->sql->single("SELECT * FROM `ip` WHERE `id` = '$insert_id'");
        $this->sql->query("INSERT INTO `ip_history` (`ip_id`,`date`,`user_id`) VALUES ('$insert_id','{$this->date}','{$this->user_id}') ON DUPLICATE KEY UPDATE `views` = `views` + 1");
        if ($this->ip["banned"]) {
            $this->error("403");
        }
        return $insert_id;
    }

    private function get_id()
    {
        $id = session_id();
        $language = "";
        if (isset($_SERVER["HTTP_ACCEPT_LANGUAGE"])) {
            $language = $this->sql->escape($_SERVER["HTTP_ACCEPT_LANGUAGE"]);
        }
        $user_agent = "";
        if (isset($_SERVER["HTTP_USER_AGENT"])) {
            $user_agent = $this->sql->escape($_SERVER["HTTP_USER_AGENT"]);
        }
        $this->sql->query("INSERT INTO `sessions_app` (`session_id`,`ip_id`,`user_id`,`user_agent`)
		VALUES ('$id','{$this->ip_id}','{$this->user_id}','$user_agent')
		ON DUPLICATE KEY UPDATE
			`ip_id` = '{$this->ip_id}',
			`views` = `views`+1,
			`language` = '$language',
			`user_agent` = '$user_agent'");
        $this->session = $this->sql->single("SELECT * FROM `sessions_app` WHERE `session_id` = '$id'");
        return $id;
    }

    public function user_id()
    {
        $id = session_id();
        $result = $this->sql->query("SELECT `user_id` FROM `sessions_app` WHERE `session_id` = '$id'");
        if (!$this->sql->count($result)) {
            return 0;
        }
        return $this->sql->assoc($result)["user_id"];
    }

    private function get_user_id()
    {
        $discord_id = $this->user_id();
        if (!$discord_id) {
            return 0;
        }
        $this->loggedin = true;
        $this->sql->query("UPDATE `users` SET `views` = `views` + 1 WHERE `discord_id` = '$discord_id'");
        $this->user = $this->sql->single("SELECT * FROM `users` WHERE `discord_id` = '$discord_id'");
        $this->user["discord_avatar"] = "https://cdn.discordapp.com/avatars/$discord_id/" . $this->user["discord_avatar"] . ".png";
        return $discord_id;
    }

    private function audit()
    {
        $table = "audits_" . $this->date;
        if (isset($_SERVER["REQUEST_URI"])) {
            $request_uri = $_SERVER["HTTP_HOST"] . $_SERVER["REQUEST_URI"];
        } else {
            global $argv;
            $request_uri = $_SERVER["PWD"] . "/" . implode(" ", $argv);
        }
        $request_uri = $this->sql->escape($request_uri);
        $this->sql->query("INSERT INTO `$table` (`ip_id`,`user_id`,`session_id`,`request_uri`) VALUES ('{$this->ip_id}','{$this->user_id}','{$this->id}','$request_uri')");
    }

    private function validate()
    {
        if ($this->user_id != 363853952749404162) $this->error("403");
        if ($this->user["banned"]) $this->error("403");
        $this->valid = true;
    }

    public function error($code)
    {
        http_response_code($code);
        include(__DIR__ . "/../errors/error-$code.html");
        exit();
    }

    public function logout()
    {
        $id = $this->id;
        $this->sql->query("UPDATE `sessions_app` SET `user_id` = 0 WHERE `session_id` = '$id'");
        $this->redirect("https://login.discommand.com/");
    }

    public function header($title = "Discommand | Bot Control Panel")
    {
        require_once(__DIR__ . "/includes/header.php");
        $header($title);
    }

    public function footer($customjs = [])
    {
        require_once(__DIR__ . "/includes/footer.php");
    }

    public function redirect($location)
    {
        header("Location: $location", true, 302);
        exit();
    }

    public function __destruct()
    {
        $this->close();
    }
}

