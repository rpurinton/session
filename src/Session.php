<?php

declare(strict_types=1);

namespace RPurinton;

use RPurinton\{Log, MySQL, User};

class Session implements \SessionHandlerInterface
{
    public ?User $user = null;

    public function __construct(string $domain, bool $allow_insecure = false, bool $json_error = true, public ?MySQL $sql = null)
    {
        Log::install();
        if (!$sql) $this->sql = MySQL::connect();
        if (session_status() === PHP_SESSION_ACTIVE) return;
        if (headers_sent()) {
            throw new \RuntimeException('Cannot start session: headers already sent.');
        }

        if (session_status() === PHP_SESSION_DISABLED) {
            throw new \RuntimeException('Cannot start session: sessions are disabled.');
        }

        session_set_save_handler(
            $this->open(...),
            $this->close(...),
            $this->read(...),
            $this->write(...),
            $this->destroy(...),
            $this->gc(...)
        );

        register_shutdown_function('session_write_close');
        session_name(str_replace(".", "", $domain));
        session_set_cookie_params([
            'lifetime' => 99999999,
            'path' => '/',
            'domain' => $domain,
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);

        session_start();

        if (isset($_SESSION['user_id'])) {
            $this->user = User::getById($this->sql, $_SESSION['user_id']);
            if ($this->user) return;
        }

        session_destroy();

        if ($allow_insecure) return;
        if ($json_error) {
            header('HTTP/1.1 401 Unauthorized');
            echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
            exit;
        }

        header('Location: /login/');
        exit;
    }

    public function open(string $path, string $name): bool
    {
        return true;
    }

    public function read(string $id): string|false
    {
        $query = "SELECT data FROM sessions_php WHERE id = ? LIMIT 1";
        $result = $this->sql->prepareAndExecute($query, [$id]);
        if (!$result) {
            return false;
        }
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
}
