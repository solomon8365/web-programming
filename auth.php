<?php
require_once __DIR__ . '/db.php';
session_start();

function currentUser(): ?array
{
    return $_SESSION['user'] ?? null;
}

function requireLogin(): void
{
    if (!currentUser()) {
        header('Location: index.php?page=login');
        exit;
    }
}

function userRole(): string
{
    $u = currentUser();

    return $u['role'] ?? 'admin';
}

function isAdmin(): bool
{
    return currentUser() !== null && userRole() === 'admin';
}

function isCustomer(): bool
{
    return currentUser() !== null && userRole() === 'customer';
}

function customerAccountCustomerId(): ?int
{
    if (!isCustomer()) {
        return null;
    }
    $id = currentUser()['customer_id'] ?? null;

    return $id !== null && $id !== '' ? (int) $id : null;
}

function requireAdmin(): void
{
    if (!currentUser()) {
        header('Location: index.php?page=admin_login');
        exit;
    }
    if (!isAdmin()) {
        header('Location: index.php?page=dashboard');
        exit;
    }
}

function requireCustomer(): void
{
    if (!currentUser()) {
        header('Location: index.php?page=customer_login');
        exit;
    }
    if (!isCustomer()) {
        header('Location: index.php?page=dashboard');
        exit;
    }
}

/**
 * Sign in with optional portal restriction.
 *
 * @param string|null $portal 'admin', 'customer', or null for any role (e.g. post-registration)
 *
 * @return string|null null on success; otherwise 'empty', 'invalid_credentials', or 'wrong_portal'
 */
function loginForPortal(string $username, string $password, ?string $portal): ?string
{
    $username = trim($username);
    if ($username === '' || $password === '') {
        return 'empty';
    }

    $pdo = getPDO();
    $stmt = $pdo->prepare('SELECT * FROM users WHERE username = :username LIMIT 1');
    $stmt->execute(['username' => $username]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($password, $user['password'])) {
        return 'invalid_credentials';
    }

    $role = $user['role'] ?? 'admin';
    if ($portal === 'admin' && $role !== 'admin') {
        return 'wrong_portal';
    }
    if ($portal === 'customer' && $role !== 'customer') {
        return 'wrong_portal';
    }

    unset($user['password']);
    $_SESSION['user'] = $user;

    return null;
}

/** @deprecated Prefer loginForPortal with an explicit portal for new code */
function login(string $username, string $password): bool
{
    return loginForPortal($username, $password, null) === null;
}

function logout(): void
{
    session_unset();
    session_destroy();
    header('Location: index.php?page=login');
    exit;
}
