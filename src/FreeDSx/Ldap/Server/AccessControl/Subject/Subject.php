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

namespace FreeDSx\Ldap\Server\AccessControl\Subject;

use Closure;

/**
 * Factory for common subject matchers.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class Subject
{
    private function __construct() {}

    /**
     * Matches any identity, authenticated or anonymous.
     */
    public static function anyone(): SubjectMatcherInterface
    {
        return new AnySubjectMatcher();
    }

    /**
     * Matches unauthenticated (anonymous) identities only.
     */
    public static function anonymous(): SubjectMatcherInterface
    {
        return new AnonymousSubjectMatcher();
    }

    /**
     * Matches any successfully authenticated identity.
     */
    public static function authenticated(): SubjectMatcherInterface
    {
        return new AuthenticatedSubjectMatcher();
    }

    /**
     * Matches when the bound DN equals the target entry DN (case-insensitive).
     */
    public static function self(): SubjectMatcherInterface
    {
        return new SelfSubjectMatcher();
    }

    /**
     * Matches a specific bound DN (case-insensitive).
     */
    public static function dn(string $dn): SubjectMatcherInterface
    {
        return new DnSubjectMatcher($dn);
    }

    /**
     * Matches when the bound DN is within a given subtree (case-insensitive).
     */
    public static function dnSubtree(string $dn): SubjectMatcherInterface
    {
        return new DnSubtreeSubjectMatcher($dn);
    }

    /**
     * Matches when the bound DN is a member of the given LDAP group entry.
     *
     * The backend is injected by the framework at server-start time.
     *
     * @param int $cacheTtl Seconds a membership read is reused for, which is also how long dropping a member may take
     *                      to bite; zero reads the group entry every time.
     */
    public static function group(
        string $groupDn,
        string $memberAttribute = 'member',
        int $cacheTtl = 5,
    ): SubjectMatcherInterface {
        return new GroupSubjectMatcher(
            $groupDn,
            $memberAttribute,
            $cacheTtl,
        );
    }

    /**
     * Delegates subject matching to a user-supplied closure.
     *
     * @param Closure(mixed, mixed): bool $callback
     */
    public static function callback(Closure $callback): SubjectMatcherInterface
    {
        return new CallbackSubjectMatcher($callback);
    }
}
