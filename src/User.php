<?php

namespace RPurinton;

use RPurinton\MySQL;

class User
{

    public function __construct(
        private MySQL $sql,
        public int $id,
        public array $data = [],
    ) {}

    public function save(): bool
    {
        $data = $this->sql->escape(json_encode($this->data, JSON_PRETTY_PRINT));
        $this->sql->query("REPLACE INTO `users` SET `data` = '$data' WHERE `id` = '{$this->id}'");
        return true;
    }

    public static function get(MySQL $sql, string $id): ?self
    {
        $id = $sql->escape($id);
        $data = json_decode($sql->fetch_one("SELECT `data` FROM `users` WHERE `id` = '$id'"), true);
        if ($data !== null) return new self($sql, $id, $data);
        return null;
    }
}
