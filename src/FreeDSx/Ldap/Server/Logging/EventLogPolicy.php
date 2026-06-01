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

/**
 * Immutable set of {@see ServerEvent} cases the server should emit.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EventLogPolicy
{
    /**
     * Per-operation success records. Toggle on via {@see EventLogPolicy::withAuditTrail()} to enable.
     *
     * @var ServerEvent[]
     */
    private const AUDIT_TRAIL_EVENTS = [
        ServerEvent::EntryAdded,
        ServerEvent::EntryModified,
        ServerEvent::EntryDeleted,
        ServerEvent::EntryRenamed,
        ServerEvent::SearchAuthorized,
        ServerEvent::CompareCompleted,
    ];

    /**
     * @param array<string, true> $enabled Keyed by ServerEvent->value quick lookup.
     */
    public function __construct(
        private array $enabled = [],
        private bool $includeExceptionTraces = false,
    ) {}

    public static function default(): self
    {
        return self::none()->enable(
            ServerEvent::BindSuccess,
            ServerEvent::BindFailure,
            ServerEvent::BindAnonymous,
            ServerEvent::StartTlsSucceeded,
            ServerEvent::StartTlsFailed,
            ServerEvent::PasswordModifySuccess,
            ServerEvent::PasswordModifyFailed,
            ServerEvent::AuthorizationDeniedWrite,
            ServerEvent::AuthorizationDeniedRead,
            ServerEvent::ProxyAuthorizationDenied,
            ServerEvent::CriticalControlRejected,
            ServerEvent::SchemaViolation,
            ServerEvent::NoticeOfDisconnectSent,
            ServerEvent::WriteTimeout,
            ServerEvent::PasswordPolicyAccountLocked,
            ServerEvent::PasswordPolicyAccountUnlocked,
            ServerEvent::PasswordPolicyExpired,
            ServerEvent::PasswordPolicyMustChange,
            ServerEvent::PasswordPolicyGraceLogin,
            ServerEvent::PasswordPolicyChangeRejected,
        );
    }

    public static function all(): self
    {
        return self::none()->enable(...ServerEvent::cases());
    }

    public static function none(): self
    {
        return new self([]);
    }

    public function enable(ServerEvent ...$events): self
    {
        $next = $this->enabled;
        foreach ($events as $event) {
            $next[$event->value] = true;
        }

        return new self(
            $next,
            $this->includeExceptionTraces,
        );
    }

    public function disable(ServerEvent ...$events): self
    {
        $next = $this->enabled;
        foreach ($events as $event) {
            unset($next[$event->value]);
        }

        return new self(
            $next,
            $this->includeExceptionTraces,
        );
    }

    public function withAuditTrail(): self
    {
        return $this->enable(...self::AUDIT_TRAIL_EVENTS);
    }

    public function withExceptionTraces(): self
    {
        return new self(
            $this->enabled,
            true,
        );
    }

    public function isEnabled(ServerEvent $event): bool
    {
        return isset($this->enabled[$event->value]);
    }

    public function includesExceptionTraces(): bool
    {
        return $this->includeExceptionTraces;
    }
}
