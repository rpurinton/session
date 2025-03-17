<?php

declare(strict_types=1);

namespace RPurinton;

use ReturnTypeWillChange;
use RPurinton\{Log, Config, MySQL, User, DiscordOAuth2};

class Session implements \SessionHandlerInterface
{
    public array $config = [];
    public ?User $user = null;
    public array $grants = [];

    public function __construct(bool $allow_insecure = false, bool $json_error = true, public ?MySQL $sql = null)
    {
        $this->config = Config::get("Session");
        if (!$sql) $this->sql = MySQL::connect();
        if (session_status() === PHP_SESSION_ACTIVE) return;
        if (headers_sent()) throw new \RuntimeException('Cannot start session: headers already sent.');
        if (session_status() === PHP_SESSION_DISABLED) throw new \RuntimeException('Cannot start session: sessions are disabled.');
        session_set_save_handler(
            $this->open(...),
            $this->close(...),
            $this->read(...),
            $this->write(...),
            $this->destroy(...),
            $this->gc(...)
        );
        register_shutdown_function('session_write_close');
        session_name(str_replace(".", "", $this->config['domain']));
        session_set_cookie_params($this->config);
        session_start();
        if (isset($_SESSION['user_id'])) {
            $this->user = User::get($this->sql, $_SESSION['user_id']);
            if ($this->user) {
                $this->audit(false);
                $this->user->save();
                return;
            }
        }
        if ($allow_insecure) return;
        session_destroy();
        if ($json_error) {
            header('HTTP/1.1 401 Unauthorized');
            echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
            exit;
        }
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

    public function login(): void
    {
        if (!$this->user) $this->createUser();
        $this->refresh();
        header('Location: /');
        exit();
    }

    private function login_error(string $message, array $context): void
    {
        Log::error("Session::login_error() $message", $context);
        header('HTTP/1.1 403 Unauthorized');
        exit();
    }

    private function createUser(): void
    {
        $tokens = DiscordOAuth2::init();
        // ...existing token validations...
        $info = DiscordOAuth2::info($tokens['access_token']);
        // ...existing validations...
        $id = (int)$info['id'];
        // ...existing code...
        // Instead of ip2long conversions, use the raw IP string:
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP']
            ?? $_SERVER['HTTP_X_FORWARDED_FOR']
            ?? $_SERVER['REMOTE_ADDR'];
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->login_error('invalid ip', [
                'HTTP_CF_CONNECTING_IP' => $_SERVER['HTTP_CF_CONNECTING_IP'] ?? null,
                'HTTP_X_FORWARDED_FOR' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null,
                'REMOTE_ADDR' => $_SERVER['REMOTE_ADDR'] ?? null
            ]);
        }
        $this->user = new User($this->sql, $id, [
            'tokens' => $tokens,
            'info' => $info,
            'audits' => [
                'first_user_id' => $id,
                'last_user_id' => $id,
                'first_ip' => $ip,
                'last_ip' => $ip,
                'login_first' => time(),
                'login_last' => time(),
                'last_activity' => time(),
                'account_type' => 'trial',
                'trial_expires' => time() + 604800,
                'logins' => 1,
                'page_views' => 1
            ],
        ]);
        $this->user->save();
        $this->audit(true);
        $_SESSION['user_id'] = $id;
    }

    private function audit(bool $login = false): void
    {
        if (!$this->user) $this->login_error('empty user', ['user' => $this->user]);
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP']
            ?? $_SERVER['HTTP_X_FORWARDED_FOR']
            ?? $_SERVER['REMOTE_ADDR'];
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->login_error('invalid ip format', [
                'HTTP_CF_CONNECTING_IP' => $_SERVER['HTTP_CF_CONNECTING_IP'] ?? null,
                'HTTP_X_FORWARDED_FOR' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null,
                'REMOTE_ADDR' => $_SERVER['REMOTE_ADDR'] ?? null
            ]);
        }

        // Update ip_addresses table using the IP string.
        $this->sql->prepareAndExecute("
        INSERT INTO `ip_addresses`
            (`ip`, `first_user_id`, `last_user_id`, `first_login`, `last_login`, `first_activity`, `last_activity`, `logins`, `page_views`)
        VALUES
            (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, 1)
        ON DUPLICATE KEY UPDATE
            `last_user_id` = ?,
            `last_login` = CURRENT_TIMESTAMP,
            `last_activity` = CURRENT_TIMESTAMP,
            `logins` = `logins` + ?,
            `page_views` = `page_views` + 1
    ", [$ip, $this->user->id, $this->user->id, $login ? 1 : 0, $this->user->id, $login ? 1 : 0]);

        $this->sql->prepareAndExecute("
        INSERT INTO `ip_history`
            (`ip`, `user_id`, `date`, `lat`, `lon`, `city`, `country`, `continent`, `accept_language`, `user_agent`, 
             `region`, `region_code`, `postal_code`, `metro_code`, `timezone`, `logins`, `page_views`)
        VALUES (
            ?, ?, CURDATE(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1
        )
        ON DUPLICATE KEY UPDATE
            `logins` = `logins` + ?,
            `page_views` = `page_views` + 1,
            `history_id` = LAST_INSERT_ID(`history_id`)
    ", [
            $ip,
            $this->user->id,
            $_SERVER['HTTP_CF_IPLATITUDE']   ? $this->sql->escape($_SERVER['HTTP_CF_IPLATITUDE']) : null,
            $_SERVER['HTTP_CF_IPLONGITUDE']  ? $this->sql->escape($_SERVER['HTTP_CF_IPLONGITUDE']) : null,
            $_SERVER['HTTP_CF_IPCITY']       ? $this->sql->escape($_SERVER['HTTP_CF_IPCITY']) : null,
            $_SERVER['HTTP_CF_IPCOUNTRY']    ? $this->sql->escape($_SERVER['HTTP_CF_IPCOUNTRY']) : null,
            $_SERVER['HTTP_CF_IPCONTINENT']  ? $this->sql->escape($_SERVER['HTTP_CF_IPCONTINENT']) : null,
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ? $this->sql->escape($_SERVER['HTTP_ACCEPT_LANGUAGE']) : null,
            $_SERVER['HTTP_USER_AGENT']      ? $this->sql->escape($_SERVER['HTTP_USER_AGENT']) : null,
            $_SERVER['HTTP_CF_REGION']       ? $this->sql->escape($_SERVER['HTTP_CF_REGION']) : null,
            $_SERVER['HTTP_CF_REGION_CODE']  ? $this->sql->escape($_SERVER['HTTP_CF_REGION_CODE']) : null,
            $_SERVER['HTTP_CF_POSTAL_CODE']  ? $this->sql->escape($_SERVER['HTTP_CF_POSTAL_CODE']) : null,
            $_SERVER['HTTP_CF_METRO_CODE']  ? $this->sql->escape($_SERVER['HTTP_CF_METRO_CODE']) : null,
            $_SERVER['HTTP_CF_TIMEZONE']     ? $this->sql->escape($_SERVER['HTTP_CF_TIMEZONE']) : null,
            $login ? 1 : 0  // for the ON DUPLICATE KEY UPDATE increment
        ]);
        $ip_history_id = $this->sql->last_insert_id();

        $this->sql->prepareAndExecute("
        INSERT INTO `audits`
            (`ip`, `history_id`, `user_id`, `request_uri`)
        VALUES
            (?, ?, ?, ?)
    ", [$ip, $ip_history_id, $this->user->id, $this->sql->escape($_SERVER['REQUEST_URI'])]);

        if (!$login) {
            $this->sql->prepareAndExecute("
            UPDATE `users`
            SET 
                `data` = JSON_SET(`data`, '$.audits.last_activity', CURRENT_TIMESTAMP),
                `data` = JSON_SET(`data`, '$.audits.page_views', JSON_EXTRACT(`data`, '$.audits.page_views') + 1),
                `data` = JSON_SET(`data`, '$.audits.last_ip', ?),
                `data` = JSON_SET(`data`, '$.audits.last_history_id', ?)
            WHERE `id` = ?
        ", [$ip, $ip_history_id, $this->user->id]);
        }

        $this->user->data = json_decode($this->sql->fetch_one("SELECT `data` FROM `users` WHERE `id` = '{$this->user->id}'"), true);
    }

    public function refresh(): void
    {
        if ($this->user->data['tokens']['expires_at'] < time()) {
            if (empty($this->user->data['tokens']['refresh_token'])) $this->login_error('empty refresh_token', ['tokens' => $this->user->data['tokens']]);
            $refresh = DiscordOauth2::refresh($this->user->data['tokens']['refresh_token']);
            if (empty($refresh['access_token'])) $this->login_error('empty access_token', ['refresh' => $refresh]);
            if (empty($refresh['expires_in'])) $this->login_error('empty expires_in', ['refresh' => $refresh]);
            $refresh['expires_at'] = time() + $refresh['expires_in'];
            $this->user->data['tokens'] = $refresh;
        }
        $info = DiscordOAuth2::info($this->user->data['tokens']['access_token']);
        if (empty($info['id'])) $this->login_error('empty id', ['info' => $info]);
        if (empty($info['avatar'])) $this->login_error('empty avatar', ['info' => $info]);
        $info['avatar_url'] = "https://cdn.discordapp.com/avatars/{$info['id']}/{$info['avatar']}.png";
        $this->user->data['info'] = $info;
        $this->user->save();
    }

    public function logout(): void
    {
        session_destroy();
        header('Location: /');
        exit;
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
        $maxRetries = 3;
        $attempt = 0;
        while ($attempt < $maxRetries) {
            try {
                $this->sql->transaction(function () use ($id, $access, $data) {
                    // Lock the row and get existing session data.
                    $lockQuery = "SELECT data FROM sessions_php WHERE id = ? FOR UPDATE";
                    $result = $this->sql->prepareAndExecute($lockQuery, [$id]);
                    $existingData = "";
                    if ($row = $result->fetch_assoc()) {
                        $existingData = $row['data'];
                    }
                    // Merge existing data with new data.
                    $mergedData = $this->mergeSessionData($existingData, $data);

                    $query = "REPLACE INTO sessions_php (id, access, data) VALUES (?, ?, ?)";
                    $this->sql->prepareAndExecute($query, [$id, $access, $mergedData]);
                });
                return true;
            } catch (\RPurinton\Exceptions\MySQLException $e) {
                if (strpos($e->getMessage(), 'Deadlock') !== false) {
                    $attempt++;
                    usleep(100000); // wait 100ms before retrying
                    if ($attempt === $maxRetries) {
                        throw $e; // rethrow error after max retries
                    }
                } else {
                    throw $e; // other exceptions are not retriable
                }
            }
        }
        return false;
    }

    /**
     * Convert serialized PHP session data into an associative array.
     */
    private function unserializeSessionData(string $session_data): array
    {
        // Backup current session data
        $backup = $_SESSION;
        // Clear session array so session_decode() sets only from string.
        $_SESSION = [];
        session_decode($session_data);
        $data = $_SESSION;
        // Restore the original session data
        $_SESSION = $backup;
        return $data;
    }

    /**
     * Convert an associative array back into PHP session format.
     */
    private function serializeSessionData(array $data): string
    {
        $session_data = '';
        foreach ($data as $key => $value) {
            $session_data .= $key . '|' . serialize($value);
        }
        return $session_data;
    }

    /**
     * Merge two session data strings.
     */
    private function mergeSessionData(string $existing, string $new): string
    {
        $oldData = $this->unserializeSessionData($existing);
        $newData = $this->unserializeSessionData($new);
        // New data overrides existing keys.
        $merged = array_merge($oldData, $newData);
        return $this->serializeSessionData($merged);
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
