<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\Logging;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\OperationType;
use Psr\Log\LogLevel;

/**
 * Catalog of structured server events emitted via {@see EventLogger}.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum ServerEvent: string
{
    case BindSuccess                    = 'bind.success';
    case BindFailure                    = 'bind.failure';
    case BindAnonymous                  = 'bind.anonymous';
    case StartTlsSucceeded              = 'starttls.succeeded';
    case StartTlsFailed                 = 'starttls.failed';
    case EntryAdded                     = 'entry.added';
    case EntryModified                  = 'entry.modified';
    case EntryDeleted                   = 'entry.deleted';
    case EntryRenamed                   = 'entry.renamed';
    case SearchAuthorized               = 'search.authorized';
    case CompareCompleted               = 'compare.completed';
    case PasswordModifySuccess          = 'password_modify.success';
    case PasswordModifyFailed           = 'password_modify.failed';
    case AuthorizationDeniedWrite       = 'authz.denied.write';
    case AuthorizationDeniedRead        = 'authz.denied.read';
    case ProxyAuthorizationDenied       = 'authz.denied.proxy';
    case CriticalControlRejected        = 'control.critical.rejected';
    case SchemaViolation                = 'schema.violation';
    case NoticeOfDisconnectSent         = 'session.disconnect_notice';
    case WriteTimeout                   = 'session.write_timeout';
    case PasswordPolicyAccountLocked    = 'password_policy.account_locked';
    case PasswordPolicyAccountUnlocked  = 'password_policy.account_unlocked';
    case PasswordPolicyExpired          = 'password_policy.expired';
    case PasswordPolicyMustChange       = 'password_policy.must_change';
    case PasswordPolicyGraceLogin       = 'password_policy.grace_login';
    case PasswordPolicyChangeRejected   = 'password_policy.change_rejected';

    public function level(): string
    {
        return match ($this) {
            self::PasswordPolicyAccountLocked => LogLevel::WARNING,
            self::BindFailure,
            self::StartTlsFailed,
            self::PasswordModifyFailed,
            self::AuthorizationDeniedWrite,
            self::AuthorizationDeniedRead,
            self::ProxyAuthorizationDenied,
            self::CriticalControlRejected,
            self::SchemaViolation,
            self::NoticeOfDisconnectSent,
            self::WriteTimeout,
            self::PasswordPolicyExpired,
            self::PasswordPolicyChangeRejected => LogLevel::NOTICE,
            default => LogLevel::INFO,
        };
    }

    public function messageTemplate(): string
    {
        return $this->value;
    }

    /**
     * Maps a write {@see OperationType} to its corresponding success event; returns null for non-write types.
     */
    public static function fromWriteOperationType(OperationType $type): ?self
    {
        return match ($type) {
            OperationType::Add => self::EntryAdded,
            OperationType::Modify => self::EntryModified,
            OperationType::Delete => self::EntryDeleted,
            OperationType::ModifyDn => self::EntryRenamed,
            default => null,
        };
    }

    /**
     * Discriminates a caught OperationException into the matching event; returns $fallback (null by default) for codes
     * that aren't audit-worthy (e.g. NO_SUCH_OBJECT, ENTRY_ALREADY_EXISTS).
     */
    public static function fromOperationException(
        OperationException $e,
        self $denialEvent,
        ?self $fallback = null,
    ): ?self {
        return match ($e->getCode()) {
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS => $denialEvent,
            ResultCode::UNAVAILABLE_CRITICAL_EXTENSION => self::CriticalControlRejected,
            default => $fallback,
        };
    }
}
