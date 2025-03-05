<?php

declare(strict_types=1);

namespace RPurinton;

use ReturnTypeWillChange;
use RPurinton\{Log, Config, MySQL, User, DiscordOAuth2};

class Session implements \SessionHandlerInterface
{
    public array $config = [];
    public ?User $user = null;

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
        session_regenerate_id();
        if (isset($_SESSION['user_id'])) {
            $this->user = User::get($this->sql, $_SESSION['user_id']);
            if ($this->user) {
                $this->refresh();
                $this->audit();
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

    public function audit(): void
    {
        $this->user->data['audits']['last_activity'] = time();
        $this->user->data['audits']['page_views']++;
        $this->user->save();
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
        if (empty($tokens['access_token'])) $this->login_error('empty access_token', ['tokens' => $tokens]);
        if (empty($tokens['refresh_token'])) $this->login_error('empty refresh_token', ['tokens' => $tokens]);
        if (empty($tokens['expires_in'])) $this->login_error('empty expires_in', ['tokens' => $tokens]);
        $tokens['expires_at'] = time() + $tokens['expires_in'];
        $info = DiscordOAuth2::info($tokens['access_token']);
        if (empty($info['id'])) $this->login_error('empty id', ['info' => $info]);
        if (empty($info['avatar'])) $this->login_error('empty avatar', ['info' => $info]);
        $id = (int)$info['id'];
        $info['avatar'] = "https://cdn.discordapp.com/avatars/{$info['id']}/{$info['avatar']}.png";
        $grants = $this->sql->fetch_one("SELECT `id` FROM `grants` WHERE `id` = '$id'");
        if (empty($grants)) $this->login_error('empty grants', ['grants' => $grants]);
        $ip_id = ip2long($_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR']);
        if ($ip_id === false) $this->login_error('invalid ip', [
            'HTTP_CF_CONNECTING_IP' => $_SERVER['HTTP_CF_CONNECTING_IP'] ?? null,
            'HTTP_X_FORWARDED_FOR' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null,
            'REMOTE_ADDR' => $_SERVER['REMOTE_ADDR'] ?? null
        ]);
        $this->user = new User($this->sql, $id, [
            'tokens' => $tokens,
            'info' => $info,
            'audits' => [
                'first_user_id' => $id,
                'last_user_id' => $id,
                'first_ip_id' => $ip_id,
                'last_ip_id' => $ip_id,
                'login_first' => time(),
                'login_last' => time(),
                'last_activity' => time(),
                'account_type' => 'trial',
                'trial_expires' => time() + 604800, // 7 days
                'logins' => 1,
                'page_views' => 1
            ],
        ]);
        $this->user->save();
        $this->get_ip_id(true);
        $_SESSION['user_id'] = $id;
    }

    private function get_ip_id(bool $login = false): void
    {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $this->login_error('invalid ip format', [
            'HTTP_CF_CONNECTING_IP' => $_SERVER['HTTP_CF_CONNECTING_IP'] ?? null,
            'HTTP_X_FORWARDED_FOR' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null,
            'REMOTE_ADDR' => $_SERVER['REMOTE_ADDR'] ?? null
        ]);
        $id = ip2long($ip);
        if ($id === false) $this->login_error('invalid ip conversion', [
            'HTTP_CF_CONNECTING_IP' => $_SERVER['HTTP_CF_CONNECTING_IP'] ?? null,
            'HTTP_X_FORWARDED_FOR' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null,
            'REMOTE_ADDR' => $_SERVER['REMOTE_ADDR'] ?? null
        ]);
        $this->sql->transaction(function () use ($id, $ip, $login) {
            $this->sql->query("
                INSERT INTO `ip_addresses`
                    (`id`, `ip`, `first_user_id`, `last_user_id`, `first_login`, `last_login`, `last_activity`, `logins`, `page_views`)
                VALUES
                    ($id, '$ip', {$this->user->id}, {$this->user->id}, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, " . ($login ? 1 : 0) . ", 1
                )
                ON DUPLICATE KEY UPDATE
                    `last_user_id` = {$this->user->id},
                    `last_login` = CURRENT_TIMESTAMP,
                    `last_activity` = CURRENT_TIMESTAMP,
                    `logins` = `logins` + " . ($login ? 1 : 0) . ",
                    `page_views` = `page_views` + 1
            ");

            $this->sql->query("
                INSERT INTO `ip_history`
                    (`ip_id`, `user_id`, `date`, `lat`, `lon`, `city`, `country`, `continent`, `accept_language`, `user_agent`, `logins`, `page_views`)
                VALUES (
                    $id,
                    {$this->user->id},
                    CURDATE(),
                    " . ($_SERVER['HTTP_CF_IPLATITUDE'] ? "'" . $this->sql->escape($_SERVER['HTTP_CF_IPLATITUDE']) . "'" : 'NULL') . ",
                    " . ($_SERVER['HTTP_CF_IPLONGITUDE'] ? "'" . $this->sql->escape($_SERVER['HTTP_CF_IPLONGITUDE']) . "'" : 'NULL') . ",
                    " . ($_SERVER['HTTP_CF_IPCITY'] ? "'" . $this->sql->escape($_SERVER['HTTP_CF_IPCITY']) . "'" : 'NULL') . ",
                    " . ($_SERVER['HTTP_CF_IPCOUNTRY'] ? "'" . $this->sql->escape($_SERVER['HTTP_CF_IPCOUNTRY']) . "'" : 'NULL') . ",
                    " . ($_SERVER['HTTP_CF_IPCONTINENT'] ? "'" . $this->sql->escape($_SERVER['HTTP_CF_IPCONTINENT']) . "'" : 'NULL') . ",
                    " . ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ? "'" . $this->sql->escape($_SERVER['HTTP_ACCEPT_LANGUAGE']) . "'" : 'NULL') . ",
                    " . ($_SERVER['HTTP_USER_AGENT'] ? "'" . $this->sql->escape($_SERVER['HTTP_USER_AGENT']) . "'" : 'NULL') . ",
                    " . ($login ? 1 : 0) . ",
                    1
                )
                ON DUPLICATE KEY UPDATE
                    `logins` = `logins` + " . ($login ? 1 : 0) . ",
                    `page_views` = `page_views` + 1,
                    `history_id` = LAST_INSERT_ID(`history_id`)
            ");
            $ip_history_id = $this->sql->last_insert_id();
            $this->sql->query("
                INSERT INTO `audits`
                    (`ip_id`, `history_id`, `user_id`, `request_uri`)
                VALUES
                    ($id, $ip_history_id, {$this->user->id}, '" . $this->sql->escape($_SERVER['REQUEST_URI']) . "')
            ");
        });
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
        $info = DiscordOAuth2::info($refresh['access_token']);
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
