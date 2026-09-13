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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\ReadEntryControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Builds RFC 4527 Pre-Read / Post-Read response controls from the entries a write kept under its lock.
 *
 * The entry goes back to the client, so read policy applies to it as it would to a search result: a write privilege
 * over an entry must not disclose what the identity may not read.
 *
 * A critical control the identity cannot satisfy fails the operation before this runs; a non-critical one degrades
 * to no control rather than failing an otherwise valid write.
 *
 * @see \FreeDSx\Ldap\Server\Middleware\OperationAuthorizationMiddleware::authorizeControlledReads()
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReadEntryControlHandler
{
    public function __construct(
        private Schema $schema,
        private AccessControlInterface $accessControl,
    ) {}

    /**
     * The pre-read control for the entry as the write found it, or null when there is none to return.
     */
    public function preRead(
        ?Entry $entry,
        ControlBag $controls,
        TokenInterface $token,
    ): ?PreReadResponseControl {
        $readable = $this->readEntry(
            Control::OID_PRE_READ,
            $entry,
            $controls,
            $token,
        );

        return $readable !== null
            ? new PreReadResponseControl($readable)
            : null;
    }

    /**
     * The post-read control for the entry as the write stored it, or null when there is none to return.
     */
    public function postRead(
        ?Entry $entry,
        ControlBag $controls,
        TokenInterface $token,
    ): ?PostReadResponseControl {
        $readable = $this->readEntry(
            Control::OID_POST_READ,
            $entry,
            $controls,
            $token,
        );

        return $readable !== null
            ? new PostReadResponseControl($readable)
            : null;
    }

    private function readEntry(
        string $oid,
        ?Entry $entry,
        ControlBag $controls,
        TokenInterface $token,
    ): ?Entry {
        $control = $controls->get($oid);

        if (!$control instanceof ReadEntryControl || $entry === null) {
            return null;
        }

        $readable = $this->accessControl->filterEntry(
            $token,
            $entry,
        );

        if ($readable === null) {
            return null;
        }

        $projection = AttributeProjection::forRequest(
            array_map(
                static fn(string $name): Attribute => new Attribute($name),
                $control->getAttributes(),
            ),
            false,
            $this->schema,
        );

        // Make a copy so live references don't leak.
        return $projection->project($readable)->makeCopy();
    }
}
