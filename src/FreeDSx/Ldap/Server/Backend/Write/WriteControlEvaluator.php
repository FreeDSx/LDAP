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

namespace FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\ReadEntry\ReadEntryControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AssertionEvaluator;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedResolver;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Evaluates a write's controls against the entries it holds under its lock, so they are atomic with the write.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class WriteControlEvaluator
{
    /**
     * The controls that read the entry a write targets.
     *
     * @var list<string>
     */
    private const ENTRY_READING_OIDS = [
        Control::OID_ASSERTION,
        Control::OID_PRE_READ,
        Control::OID_POST_READ,
    ];

    private ?Entry $target = null;

    private ?Entry $preReadEntry = null;

    private ?Entry $postReadEntry = null;

    /**
     * @param ?DerivedResolver $derived Adds the derived attributes a read-entry control asks for; none when null.
     */
    public function __construct(
        private readonly AssertionEvaluator $assertions,
        private readonly TokenInterface $token,
        private readonly ControlBag $controls,
        private readonly ?DerivedResolver $derived = null,
    ) {}

    /**
     * Holds the located entry to the assertion (RFC 4528 §3), then keeps it for a Pre-Read (RFC 4527 §3.1).
     *
     * @throws OperationException
     */
    public function evaluateTarget(Entry $current): void
    {
        $this->assertions->assertSatisfiedBy(
            $current,
            $this->controls,
            $this->token,
        );
        $this->target = $current;
        $this->preReadEntry = $this->keptFor(
            Control::OID_PRE_READ,
            $current,
        );
    }

    /**
     * Holds the entry being added to the assertion, as it is the Add's target (RFC 4528 §3), then keeps it for a Post-Read.
     *
     * @throws OperationException
     */
    public function evaluateAddition(Entry $entry): void
    {
        $this->assertions->assertSatisfiedBy(
            $entry,
            $this->controls,
            $this->token,
        );
        $this->captureResult($entry);
    }

    /**
     * Keeps the entry the write is about to store, for a Post-Read (RFC 4527 §3.2).
     */
    public function captureResult(Entry $result): void
    {
        $this->postReadEntry = $this->keptFor(
            Control::OID_POST_READ,
            $result,
        );
    }

    /**
     * Whether a control the write carries reads the entry.
     */
    public function inspectsEntry(): bool
    {
        foreach (self::ENTRY_READING_OIDS as $oid) {
            if ($this->controls->has($oid)) {
                return true;
            }
        }

        return false;
    }

    public function preReadEntry(): ?Entry
    {
        return $this->preReadEntry;
    }

    public function postReadEntry(): ?Entry
    {
        return $this->postReadEntry;
    }

    /**
     * A copy, since storage may keep the very object the write goes on to change, and nothing without the control.
     */
    private function keptFor(
        string $oid,
        Entry $entry,
    ): ?Entry {
        $control = $this->controls->get($oid);
        if (!$control instanceof ReadEntryControl) {
            return null;
        }
        $kept = $entry->makeCopy();

        if ($this->derived === null) {
            return $kept;
        }

        // Subordinates are counted on the target, as a write only ever moves them along with it.
        return $this->derived->injectRequested(
            $kept,
            array_map(
                static fn(string $name): Attribute => new Attribute($name),
                $control->getAttributes(),
            ),
            $this->target,
        );
    }
}
