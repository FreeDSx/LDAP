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
use FreeDSx\Ldap\Operation\OperationType;
use Psr\Log\LogLevel;

/**
 * Catalog of structured server events emitted via {@see EventLogger}.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum ServerEvent: string
{
    case BindSuccess                    = 'ldap.bind.success';
    case BindFailure                    = 'ldap.bind.failure';
    case BindAnonymous                  = 'ldap.bind.anonymous';
    case StartTlsSucceeded              = 'ldap.starttls.succeeded';
    case StartTlsFailed                 = 'ldap.starttls.failed';
    case StartTlsBufferDiscarded        = 'ldap.starttls.buffer_discarded';
    case EntryAdded                     = 'ldap.entry.added';
    case EntryModified                  = 'ldap.entry.modified';
    case EntryDeleted                   = 'ldap.entry.deleted';
    case EntryRenamed                   = 'ldap.entry.renamed';
    case SearchAuthorized               = 'ldap.search.authorized';
    case CompareCompleted               = 'ldap.compare.completed';
    case PasswordModifySuccess          = 'ldap.password_modify.success';
    case PasswordModifyFailed           = 'ldap.password_modify.failed';
    case AuthorizationDeniedWrite       = 'ldap.authz.denied.write';
    case AuthorizationDeniedRead        = 'ldap.authz.denied.read';
    case ProxyAuthorizationDenied       = 'ldap.authz.denied.proxy';
    case CriticalControlRejected        = 'ldap.control.critical.rejected';
    case OperationRefused               = 'ldap.operation.refused';
    case SchemaViolation                = 'ldap.schema.violation';
    case SyncEntrySkipped               = 'ldap.sync.entry_skipped';
    case PagingSessionEvicted           = 'ldap.paging.session_evicted';
    case MessageDecodeFailed            = 'ldap.message.decode_failed';
    case NoticeOfDisconnectSent         = 'ldap.session.disconnect_notice';
    case PasswordPolicyAccountLocked    = 'ldap.password_policy.account_locked';
    case PasswordPolicyAccountUnlocked  = 'ldap.password_policy.account_unlocked';
    case PasswordPolicyExpired          = 'ldap.password_policy.expired';
    case PasswordPolicyMustChange       = 'ldap.password_policy.must_change';
    case PasswordPolicyGraceLogin       = 'ldap.password_policy.grace_login';
    case PasswordPolicyChangeRejected   = 'ldap.password_policy.change_rejected';
    case EntrySkipped                   = 'storage.import.entry_skipped';
    case BulkImportCompleted            = 'storage.import.completed';
    case BulkImportFailed               = 'storage.import.failed';
    case JournalPruned                  = 'storage.journal.pruned';
    case JournalPruneFailed             = 'storage.journal.prune_failed';
    case WriteTimeout                   = 'server.client.write_timeout';
    case IdleTimeout                    = 'server.client.idle_timeout';

    public function level(): string
    {
        return match ($this) {
            self::PasswordPolicyAccountLocked,
            self::StartTlsBufferDiscarded,
            self::SyncEntrySkipped,
            self::BulkImportFailed,
            self::JournalPruneFailed => LogLevel::WARNING,
            self::BindFailure,
            self::StartTlsFailed,
            self::PasswordModifyFailed,
            self::AuthorizationDeniedWrite,
            self::AuthorizationDeniedRead,
            self::ProxyAuthorizationDenied,
            self::CriticalControlRejected,
            self::OperationRefused,
            self::SchemaViolation,
            self::MessageDecodeFailed,
            self::NoticeOfDisconnectSent,
            self::WriteTimeout,
            self::IdleTimeout,
            self::PagingSessionEvicted,
            self::PasswordPolicyExpired,
            self::PasswordPolicyChangeRejected => LogLevel::NOTICE,
            default => LogLevel::INFO,
        };
    }

    /**
     * What happened. Meant for a person reading the log. The event's name is in the record's context.
     */
    public function messageTemplate(): string
    {
        return match ($this) {
            self::BindSuccess => 'A bind authenticated a user.',
            self::BindFailure => 'A bind failed to authenticate.',
            self::BindAnonymous => 'An anonymous bind was performed.',
            self::StartTlsSucceeded => 'TLS was negotiated on the connection.',
            self::StartTlsFailed => 'A StartTLS request was rejected.',
            self::StartTlsBufferDiscarded => 'Plaintext sent behind a StartTLS request was discarded unread.',
            self::EntryAdded => 'An entry was added.',
            self::EntryModified => 'An entry was modified.',
            self::EntryDeleted => 'An entry was deleted.',
            self::EntryRenamed => 'An entry was renamed or moved.',
            self::SearchAuthorized => 'A search completed after authorization.',
            self::CompareCompleted => 'A compare completed.',
            self::PasswordModifySuccess => 'A password was modified.',
            self::PasswordModifyFailed => 'A password modify was rejected.',
            self::AuthorizationDeniedWrite => 'Access control denied a write.',
            self::AuthorizationDeniedRead => 'Access control denied a read.',
            self::ProxyAuthorizationDenied => 'Proxied authorization was denied.',
            self::CriticalControlRejected => 'A critical control the server does not support was rejected.',
            self::OperationRefused => 'An operation was refused before it was processed.',
            self::SchemaViolation => 'An add or modify violated the schema.',
            self::SyncEntrySkipped => 'An entry was left out of a content synchronization.',
            self::PagingSessionEvicted => 'The least recently started paged search was discarded to make room for another.',
            self::MessageDecodeFailed => 'A message could not be decoded.',
            self::NoticeOfDisconnectSent => 'A notice of disconnection was sent to the client.',
            self::PasswordPolicyAccountLocked => 'An account was locked by the password policy.',
            self::PasswordPolicyAccountUnlocked => 'A locked account was unlocked once its lockout expired.',
            self::PasswordPolicyExpired => 'A bind was refused because the password has expired.',
            self::PasswordPolicyMustChange => 'The password was reset and must be changed before anything else.',
            self::PasswordPolicyGraceLogin => 'A bind used one of an expired password\'s grace logins.',
            self::PasswordPolicyChangeRejected => 'A password change was rejected by the password policy.',
            self::EntrySkipped => 'Seeding left an entry that already exists untouched.',
            self::BulkImportCompleted => 'Seeding committed.',
            self::BulkImportFailed => 'Seeding failed and was rolled back.',
            self::JournalPruned => 'The change journal was pruned.',
            self::JournalPruneFailed => 'Pruning the change journal failed.',
            self::WriteTimeout => 'The connection was closed because the client stopped reading.',
            self::IdleTimeout => 'The connection was closed after being idle too long.',
        };
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
