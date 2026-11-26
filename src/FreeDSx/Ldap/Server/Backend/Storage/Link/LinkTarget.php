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

namespace FreeDSx\Ldap\Server\Backend\Storage\Link;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Matching\NameAndOptionalUid;

use function strlen;
use function substr;

/**
 * The entry a linked value names, and the optional uid a Name and Optional UID value carries after it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LinkTarget
{
    /**
     * The longest uid kept, in bits, which leaves the link table's unique key within what MySQL can index.
     */
    public const MAX_UID_BITS = 1023;

    /**
     * @param string $name The name as the value spells it.
     * @param string $lcDn The name's canonical form, which is how the entry table keys it.
     * @param string $uid The uid as the link table keeps it: empty when absent, otherwise '#' followed by its bits.
     */
    private function __construct(
        public string $name,
        public string $lcDn,
        public string $uid,
    ) {}

    /**
     * The target a value names, splitting off its uid only when the attribute's values carry one.
     */
    public static function of(
        string $value,
        bool $carriesUid,
    ): self {
        if (!$carriesUid) {
            return new self(
                $value,
                Dn::normalized($value),
                '',
            );
        }
        $parsed = NameAndOptionalUid::parse($value);

        return new self(
            $parsed->name,
            Dn::normalized($parsed->name),
            $parsed->uid === null
                ? ''
                : '#' . substr(
                    $parsed->uid,
                    1,
                    -2,
                ),
        );
    }

    /**
     * The value a stored link gives back: the entry's current name, then the uid it was written with.
     */
    public static function valueOf(
        string $dn,
        string $uid,
    ): string {
        return $uid === ''
            ? $dn
            : $dn . "#'" . substr(
                $uid,
                1,
            ) . "'B";
    }

    /**
     * Two values are one link when they name the same entry with the same uid, however either is spelled.
     */
    public function identity(): string
    {
        return self::identityOf(
            $this->lcDn,
            $this->uid,
        );
    }

    /**
     * The identity of a stored link, from the canonical DN it names and the uid it keeps.
     */
    public static function identityOf(
        string $lcDn,
        string $uid,
    ): string {
        return $lcDn . "\0" . $uid;
    }

    /**
     * Whether the link table can keep the uid.
     */
    public function isStorable(): bool
    {
        return strlen($this->uid) <= self::MAX_UID_BITS + 1;
    }

    /**
     * @throws OperationException when the uid is longer than the link table keeps
     */
    public function assertStorable(): void
    {
        if ($this->isStorable()) {
            return;
        }

        throw new OperationException(
            'A linked value carries a uid longer than can be stored.',
            ResultCode::ADMIN_LIMIT_EXCEEDED,
        );
    }
}
