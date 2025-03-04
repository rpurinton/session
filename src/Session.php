<?php

declare(strict_types=1);

namespace RPurinton;

use RPurinton\{Log, Config, MySQL, User, DiscordOauth2};

class Session implements \SessionHandlerInterface
{
    public array $config = [];
    public ?User $user = null;

    public function __construct(bool $allow_insecure = false, bool $json_error = true, public ?MySQL $sql = null)
    {
        Log::trace("Session::__construct()", ['allow_insecure' => $allow_insecure, 'json_error' => $json_error]);
        $this->config = Config::get("Session", []);
        Log::trace("Session::__construct()", ['config' => $this->config]);
        if (!$sql) $this->sql = MySQL::connect();
        Log::trace("Session::__construct()", ['sql' => $this->sql]);
        if (session_status() === PHP_SESSION_ACTIVE) return;
        Log::trace("Session::__construct()", ['session_status' => session_status()]);
        if (headers_sent()) throw new \RuntimeException('Cannot start session: headers already sent.');
        Log::trace("Session::__construct()", ['headers_sent' => headers_sent()]);
        if (session_status() === PHP_SESSION_DISABLED) throw new \RuntimeException('Cannot start session: sessions are disabled.');
        Log::trace("Session::__construct()", ['session_status' => session_status()]);
        session_set_save_handler(
            $this->open(...),
            $this->close(...),
            $this->read(...),
            $this->write(...),
            $this->destroy(...),
            $this->gc(...)
        );
        Log::trace("Session::__construct()", ['session_set_save_handler' => 'success']);
        register_shutdown_function('session_write_close');
        Log::trace("Session::__construct()", ['register_shutdown_function' => 'success']);
        session_name(str_replace(".", "", $this->config['domain']));
        Log::trace("Session::__construct()", ['session_name' => session_name()]);
        session_set_cookie_params($this->config);
        Log::trace("Session::__construct()", ['session_set_cookie_params' => session_get_cookie_params()]);
        session_start();
        Log::trace("Session::__construct()", ['session_start' => 'success']);
        if (isset($_SESSION['user_id'])) {
            Log::trace("Session::__construct()", ['user_id' => $_SESSION['user_id']]);
            $this->user = User::getById($this->sql, $_SESSION['user_id']);
            Log::trace("Session::__construct()", ['user' => $this->user]);
            if ($this->user) return;
        }
        Log::trace("Session::__construct()", ['user' => 'null']);
        Log::trace("Session::__construct()", ['allow_insecure' => $allow_insecure]);
        if ($allow_insecure) return;
        session_destroy();
        Log::trace("Session::__construct()", ['session_destroy' => 'success']);
        if ($json_error) {
            Log::trace("Session::__construct()", ['json_error' => $json_error]);
            header('HTTP/1.1 401 Unauthorized');
            Log::trace("Session::__construct()", ['header' => 'HTTP/1.1 401 Unauthorized']);
            echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
            Log::trace("Session::__construct()", ['json' => json_encode(['status' => 'error', 'message' => 'Unauthorized'])]);
            exit;
        }
        Log::trace("Session::__construct()", ['header' => 'Location: /login/']);
        header('Location: /login/');
        exit;
    }

    public static function connect(bool $allow_insecure = false, bool $json_error = true): Session
    {
        return new Session($allow_insecure, $json_error);
    }

    public function open(string $path, string $name): bool
    {
        return true;
    }

    public function read(string $id): string|false
    {
        $query = "SELECT `data` FROM `sessions_php` WHERE `id` = ? LIMIT 1";
        $result = $this->sql->prepareAndExecute($query, [$id]);
        if (!$result) return false;
        $row = $result->fetch_assoc();
        return $row['data'] ?? "";
    }

    public function write(string $id, string $data): bool
    {
        $access = time();
        $this->sql->transaction(function () use ($id, $access, $data) {
            $lockQuery = "SELECT data FROM sessions_php WHERE id = ? FOR UPDATE";
            $this->sql->prepareAndExecute($lockQuery, [$id]);
            $query = "REPLACE INTO sessions_php (id, access, data) VALUES (?, ?, ?)";
            $this->sql->prepareAndExecute($query, [$id, $access, $data]);
        });
        return true;
    }

    public function destroy(string $id): bool
    {
        $query = "DELETE FROM sessions_php WHERE id = ?";
        $this->sql->prepareAndExecute($query, [$id]);
        return true;
    }

    public function close(): bool
    {
        return true;
    }

    public function gc(int $max_lifetime): int|false
    {
        $stale = time() - $max_lifetime;
        $query = "DELETE FROM sessions_php WHERE access < ?";
        $this->sql->prepareAndExecute($query, [$stale]);
        return $this->sql->affected_rows();
    }

    public function __destruct()
    {
        $this->close();
    }

    public function login(): bool
    {
        $result = DiscordOAuth2::init();
        print_r($result);
    }

    public function logout(): bool
    {
        return true;
    }
}
