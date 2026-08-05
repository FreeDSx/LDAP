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

namespace FreeDSx\Ldap\Server\AccessControl\Rule;

use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;

/**
 * An ordered access control rule gating use of a privileged extended operation by OID.
 *
 * Extended operations name no entry, so this rule carries no target and can only depend on the subject.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ExtendedOperationRule
{
    use TargetlessSubjectTrait;

    /**
     * @param string[] $extendedOpOids Extended operation request OIDs; empty matches all extended operations.
     */
    public function __construct(
        public Effect $effect,
        public SubjectMatcherInterface $subject,
        public array $extendedOpOids,
    ) {
        self::assertSubjectNeedsNoTarget($subject);
    }

    public static function allow(
        SubjectMatcherInterface $subject,
        string ...$extendedOpOids,
    ): self {
        return new self(
            Effect::Allow,
            $subject,
            $extendedOpOids,
        );
    }

    public static function deny(
        SubjectMatcherInterface $subject,
        string ...$extendedOpOids,
    ): self {
        return new self(
            Effect::Deny,
            $subject,
            $extendedOpOids,
        );
    }
}
