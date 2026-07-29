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
 * An ordered access control rule gating reads of a schema attribute marked X-CONFIDENTIAL.
 *
 * An empty $attributes list matches every confidential attribute.
 *
 * Unlike the other rules this carries no target: confidentiality is answered before a search runs, when no
 * entry is in hand, so it can only depend on the subject.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ConfidentialAccessRule
{
    /**
     * @param string[] $attributes Attribute names. Empty matches every confidential attribute.
     */
    private function __construct(
        public Effect $effect,
        public SubjectMatcherInterface $subject,
        public array $attributes,
    ) {}

    public static function allow(
        SubjectMatcherInterface $subject,
        string ...$attributes,
    ): self {
        return new self(
            Effect::Allow,
            $subject,
            $attributes,
        );
    }

    /**
     * Reads the empty attribute list aloud, for the common grant covering every confidential attribute.
     */
    public static function allowAny(SubjectMatcherInterface $subject): self
    {
        return self::allow($subject);
    }

    public static function deny(
        SubjectMatcherInterface $subject,
        string ...$attributes,
    ): self {
        return new self(
            Effect::Deny,
            $subject,
            $attributes,
        );
    }
}
