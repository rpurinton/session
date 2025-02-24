<?php

namespace RPurinton;

use RPurinton\MySQL;

class User
{
    public ?string $password = null;

    public function __construct(
        public MySQL $sql,
        public string $id,
        public string $username,
        public array $data = [],
    ) {}

    public static function authenticate(MySQL $sql, string $username, string $password): ?self
    {
        $username = $sql->escape($username);
        $user = $sql->fetch_row("SELECT * FROM users WHERE username = '$username'");
        if ($user) {
            if (password_verify($password, $user['password'])) {
                return new self($sql, $user['id'], $username, json_decode($user['data'], true));
            }
        }
        return null;
    }

    public function save(): bool
    {
        $data = $this->sql->escape(json_encode($this->data, JSON_PRETTY_PRINT));
        $this->sql->query("UPDATE users SET data = '$data' WHERE id = '{$this->id}'");
        if ($this->password) self::updatePassword($this->sql, $this->username, $this->password);
        return true;
    }

    public static function createUser(MySQL $sql, string $username, string $password, string $displayName, string $timezone = 'America/New_York'): void
    {
        if (self::userExists($sql, $username)) {
            throw new \RuntimeException("Username '$username' is already taken.");
        }
        $hashedPassword = password_hash(hash('sha256', $password), PASSWORD_BCRYPT);
        $query = "INSERT INTO users (id, username, password, display_name, timezone) VALUES (UUID(), ?, ?, ?, ?)";
        $sql->transaction(function () use ($sql, $query, $username, $hashedPassword, $displayName, $timezone) {
            $sql->prepareAndExecute($query, [$username, $hashedPassword, $displayName, $timezone]);
        });
    }

    public static function userExists(MySQL $sql, string $username): bool
    {
        $username = $sql->escape($username);
        $count = $sql->fetch_one("SELECT COUNT(*) FROM users WHERE username = '$username'");
        return $count > 0;
    }

    public static function updatePassword(MySQL $sql, string $username, string $newPassword): void
    {
        if (!self::userExists($sql, $username)) {
            throw new \RuntimeException("User '$username' not found.");
        }
        $hashedPassword = password_hash(hash('sha256', $newPassword), PASSWORD_BCRYPT);
        $query = "UPDATE users SET password = ? WHERE username = ?";
        $sql->transaction(function () use ($sql, $query, $hashedPassword, $username) {
            $sql->prepareAndExecute($query, [$hashedPassword, $username]);
        });
    }

    public static function deleteUser(MySQL $sql, string $username): void
    {
        if (!self::userExists($sql, $username)) {
            throw new \RuntimeException("User '$username' not found.");
        }
        $sql->transaction(function () use ($sql, $username) {
            $query = "SELECT id FROM users WHERE username = ?";
            $result = $sql->prepareAndExecute($query, [$username]);
            $rows = $result->fetch_all(MYSQLI_ASSOC);
            if (empty($rows)) {
                throw new \RuntimeException("User '$username' not found.");
            }
            $user_id = $rows[0]['id'];
            $query = "DELETE FROM tasks WHERE user_id = ?";
            $sql->prepareAndExecute($query, [$user_id]);
            $query = "DELETE FROM chat_history WHERE user_id = ?";
            $sql->prepareAndExecute($query, [$user_id]);
            $query = "DELETE FROM users WHERE id = ?";
            $sql->prepareAndExecute($query, [$user_id]);
        });
    }

    public static function listUsers(MySQL $sql): array
    {
        $users = $sql->fetch_all("SELECT id, username FROM users");
        return $users;
    }

    public static function getByUsername(MySQL $sql, string $username): ?self
    {
        $username = $sql->escape($username);
        $user = $sql->fetch_row("SELECT * FROM users WHERE username = '$username'");
        if ($user) {
            return new self(
                $sql,
                $user['id'],
                $user['username'],
                $user['data'],
            );
        }
        return null;
    }

    public static function getById(MySQL $sql, string $id): ?self
    {
        $id = $sql->escape($id);
        $user = $sql->fetch_row("SELECT * FROM users WHERE id = '$id'");
        $user['data'] = json_decode($user['data'], true);
        if ($user) {
            return new self(
                $sql,
                $user['id'],
                $user['username'],
                $user['data']
            );
        }
        return null;
    }
}
