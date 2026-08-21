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
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use FreeDSx\Ldap\Server\AccessControl\Target\TargetMatcherInterface;

/**
 * An ordered access control rule gating whether entries may leave or arrive in a container.
 *
 * Only consulted when a Modify DN changes the parent, so renaming an entry in place is never gated by these rules.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class RelocationRule
{
    /**
     * @param TargetMatcherInterface $target The container, being the old parent for Out and the new parent for In.
     * @param RelocationAccess $access Whether this covers entries leaving the container, arriving in it, or both.
     */
    public function __construct(
        public Effect $effect,
        public SubjectMatcherInterface $subject,
        public TargetMatcherInterface $target,
        public RelocationAccess $access = RelocationAccess::Both,
    ) {}

    /**
     * @param TargetMatcherInterface $target The container, being the old parent for Out and the new parent for In.
     * @param RelocationAccess $access Whether this covers entries leaving the container, arriving in it, or both.
     */
    public static function allow(
        SubjectMatcherInterface $subject,
        TargetMatcherInterface $target = new AnyTargetMatcher(),
        RelocationAccess $access = RelocationAccess::Both,
    ): self {
        return new self(
            Effect::Allow,
            $subject,
            $target,
            $access,
        );
    }

    /**
     * @param TargetMatcherInterface $target The container, being the old parent for Out and the new parent for In.
     * @param RelocationAccess $access Whether this covers entries leaving the container, arriving in it, or both.
     */
    public static function deny(
        SubjectMatcherInterface $subject,
        TargetMatcherInterface $target = new AnyTargetMatcher(),
        RelocationAccess $access = RelocationAccess::Both,
    ): self {
        return new self(
            Effect::Deny,
            $subject,
            $target,
            $access,
        );
    }
}
