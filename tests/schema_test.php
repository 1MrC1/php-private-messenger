<?php

declare(strict_types=1);

/**
 * schema.sql is what a new deployment starts from, so it has to stay in step
 * with the tables and columns the code actually uses — and it must never carry
 * rows or counters from whatever database it was generated against.
 */

function schemaAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

$root = dirname(__DIR__);
$schema = (string)file_get_contents($root . '/schema.sql');
schemaAssert($schema !== '', 'schema.sql is readable');

preg_match_all('/CREATE TABLE `([a-z_]+)`/', $schema, $matches);
$tables = $matches[1];
schemaAssert($tables !== [], 'schema.sql creates tables');

// Tables the application reads or writes.
$required = [
    'users', 'chats', 'chat_participants', 'messages',
    'message_status', 'typing_indicators', 'backup_codes',
];
$missing = array_values(array_diff($required, $tables));
schemaAssert(
    $missing === [],
    'schema.sql creates every table the application uses' .
        ($missing === [] ? '' : ': ' . implode(', ', $missing))
);

// Anything extra is either dead weight or something that should not ship.
$unexpected = array_values(array_diff($tables, $required));
schemaAssert(
    $unexpected === [],
    'schema.sql creates nothing beyond those tables' .
        ($unexpected === [] ? '' : ': ' . implode(', ', $unexpected))
);

// A foreign key parent must already exist when its child is created.
$positions = array_flip($tables);
preg_match_all('/CREATE TABLE `([a-z_]+)`(.*?)\n\)/s', $schema, $bodies, PREG_SET_ORDER);
$ordering = [];
foreach ($bodies as $body) {
    preg_match_all('/REFERENCES `([a-z_]+)`/', $body[2], $parents);
    foreach ($parents[1] as $parent) {
        if ($parent !== $body[1] && ($positions[$parent] ?? PHP_INT_MAX) > $positions[$body[1]]) {
            $ordering[] = $body[1] . ' before ' . $parent;
        }
    }
}
schemaAssert(
    $ordering === [],
    'every foreign key parent is created before its child' .
        ($ordering === [] ? '' : ': ' . implode(', ', $ordering))
);

// No data, and no counters from the database this was generated against.
// Comment lines are excluded: the header shows an example CREATE DATABASE.
$statements = implode("\n", array_filter(
    explode("\n", $schema),
    static fn(string $line): bool => !str_starts_with(ltrim($line), '--')
));
foreach (['INSERT INTO', 'AUTO_INCREMENT=', 'DEFINER', 'CREATE DATABASE', 'USE `'] as $forbidden) {
    schemaAssert(
        stripos($statements, $forbidden) === false,
        'no executable statement in schema.sql uses ' . trim($forbidden, ' `')
    );
}

// Columns the code depends on, spot-checked where a mismatch would be silent.
$expectedColumns = [
    'users' => ['username', 'email', 'password_hash', 'two_factor_secret', 'two_factor_enabled', 'who_can_message'],
    'messages' => ['chat_id', 'sender_id', 'content', 'file_path', 'reply_to_message_id', 'is_deleted'],
    'chat_participants' => ['chat_id', 'user_id', 'left_at'],
    'message_status' => ['message_id', 'user_id'],
    'backup_codes' => ['user_id', 'code', 'used'],
];
foreach ($expectedColumns as $table => $columns) {
    preg_match('/CREATE TABLE `' . $table . '`(.*?)\n\)/s', $schema, $body);
    $definition = $body[1] ?? '';
    $absent = array_values(array_filter(
        $columns,
        static fn(string $column): bool => !str_contains($definition, '`' . $column . '`')
    ));
    schemaAssert(
        $absent === [],
        $table . ' defines the columns the code queries' .
            ($absent === [] ? '' : ': missing ' . implode(', ', $absent))
    );
}

// The documented install path must actually be documented.
$readme = (string)file_get_contents($root . '/README.md');
schemaAssert(
    str_contains($readme, 'schema.sql'),
    'the README tells a new deployment to apply schema.sql'
);

echo "Schema tests passed.\n";
