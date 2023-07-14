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

namespace FreeDSx\Ldap\Control\Sync;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;
use function bin2hex;
use function count;
use function implode;
use function substr;

/**
 * Represents a syncStateValue control. RFC 4533.
 *
 * syncStateValue ::= SEQUENCE {
 *     state ENUMERATED {
 *         present (0),
 *         add (1),
 *         modify (2),
 *         delete (3)
 *     },
 *     entryUUID syncUUID,
 *     cookie    syncCookie OPTIONAL
 * }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com
 * @see https://tools.ietf.org/html/rfc4533
 */
class SyncStateControl extends Control
{
    public const STATE_PRESENT = 0;

    public const STATE_ADD = 1;

    public const STATE_MODIFY = 2;

    public const STATE_DELETE = 3;

    private ?string $decodedUuid = null;

    public function __construct(
        private readonly int $state,
        private readonly string $entryUuid,
        private readonly ?string $cookie = null
    ) {
        parent::__construct(self::OID_SYNC_STATE);
    }

    public function getState(): int
    {
        return $this->state;
    }

    public function getCookie(): ?string
    {
        return $this->cookie;
    }

    public function getEntryUuid(): string
    {
        return $this->entryUuid;
    }

    /**
     * By default, the protocol returns the binary representation of the entryUUID. This decodes that to the normal UUID
     * string representation that most are familiar with.
     */
    public function decodedUuid(): string
    {
        if ($this->decodedUuid === null) {
            $hex = bin2hex($this->entryUuid);

            $this->decodedUuid = implode('-', [
                substr($hex, 0, 8),
                substr($hex, 8, 4),
                substr($hex, 12, 4),
                substr($hex, 16, 4),
                substr($hex, 20)
            ]);
        }

        return $this->decodedUuid;
    }

    /**
     * Whether this is for adding an entry.
     *
     * **NOTE**: An "add" in this context may also mean that it was just modified / moved. It's probably safest to just
     *           treat this as an upsert operation on the target replication end.
     *
     * Description from the RFC:
     *
     *    Where DIT updates cause an entry to be added to the content, the
     *    server provides a SearchResultEntry Message that represents the entry
     *    as it appears in the content.  The message SHALL include a Sync State
     *    Control with state of add, an entryUUID containing the entry's UUID,
     *    and an optional cookie.
     *
     * The same logic applies to referrals.
     */
    public function isAdd(): bool
    {
        return $this->state === self::STATE_ADD;
    }

    /**
     * Whether this is for an entry still present (ie. unchanged).
     *
     *   For each entry that has not been changed since
     *   the previous Sync Operation, an empty SearchResultEntry is returned
     *   whose objectName reflects the entry's current DN, whose attributes
     *   field is empty, and whose Sync State Control consists of state
     *   present, an entryUUID containing the UUID of the entry, and no
     *   cookie.
     *
     *   For each reference that has not been changed since the
     *   previous Sync Operation, an empty SearchResultReference containing an
     *   empty SEQUENCE OF LDAPURL is returned with a Sync State Control
     *   consisting of state present, an entryUUID containing the UUID of the
     *   entry, and no cookie.
     */
    public function isPresent(): bool
    {
        return $this->state === self::STATE_PRESENT;
    }

    /**
     * Whether this is for an entry that has been deleted.
     *
     * Description from the RFC:
     *
     *    Where DIT updates cause an entry to be deleted from the content, the
     *    server provides a SearchResultEntry Message with no attributes.  The
     *    message SHALL include a Sync State Control with state of delete, an
     *    entryUUID containing the entry's UUID, and an optional cookie.
     *
     * The same logic applies to referrals.
     */
    public function isDelete(): bool
    {
        return $this->state === self::STATE_DELETE;
    }

    /**
     * Whether this is for an entry that has been modified.
     *
     * Description from the RFC:
     *
     *   Where DIT updates cause an entry to be modified within the content,
     *   the server provides a SearchResultEntry Message that represents the
     *   entry as it appears in the content.  The message SHALL include a Sync
     *   State Control with state of modify, an entryUUID containing the
     *   entry's UUID, and an optional cookie.
     *
     * The same logic applies to referrals.
     */
    public function isModify(): bool
    {
        return $this->state === self::STATE_MODIFY;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::sequence(
            Asn1::enumerated($this->state),
            Asn1::octetString($this->entryUuid)
        );
        if ($this->cookie !== null) {
            $this->controlValue->addChild(Asn1::octetString($this->cookie));
        }

        return parent::toAsn1();
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type): static
    {
        $sync = self::decodeEncodedValue($type);
        $count = count($sync->getChildren());
        if (!($sync instanceof SequenceType && ($count === 3 || $count === 2))) {
            throw new ProtocolException('Expected a sequence type with 2 or 3 values for a sync state control value.');
        }
        if (!(($state = $sync->getChild(0)) instanceof EnumeratedType)) {
            throw new ProtocolException('Expected an enumerated type for the state control value.');
        }
        if (!(($entryUuid = $sync->getChild(1)) instanceof OctetStringType)) {
            throw new ProtocolException('Expected an octet string type for the state control value.');
        }
        $cookie = $sync->getChild(2);
        if ($cookie && !($cookie instanceof OctetStringType)) {
            throw new ProtocolException('Expected an octet string type for the sync state cookie value.');
        }

        return self::mergeControlData(
            new static(
                $state->getValue(),
                $entryUuid->getValue(),
                $cookie ? $cookie->getValue() : null
            ),
            $type
        );
    }
}
