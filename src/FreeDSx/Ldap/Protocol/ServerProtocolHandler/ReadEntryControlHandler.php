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
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Builds RFC 4527 Pre-Read / Post-Read response controls from the entry state around a write.
 *
 * The entry goes back to the client, so read policy applies to it as it would to a search result: a write privilege
 * over an entry must not disclose what the identity may not read.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReadEntryControlHandler
{
    public function __construct(
        private LdapBackendInterface $backend,
        private Schema $schema,
        private AccessControlInterface $accessControl,
    ) {}

    /**
     * Build the pre-read control for a write, reading the target before the change (not applicable to Add).
     */
    public function preReadFor(
        Request\RequestInterface $request,
        ControlBag $controls,
        TokenInterface $token,
    ): ?PreReadResponseControl {
        $dn = $this->preReadDn($request);

        return $dn !== null
            ? $this->preRead($dn, $controls, $token)
            : null;
    }

    /**
     * Build the post-read control for a write, reading the target after the change (not applicable to Delete).
     */
    public function postReadFor(
        Request\RequestInterface $request,
        ControlBag $controls,
        TokenInterface $token,
    ): ?PostReadResponseControl {
        $dn = $this->postReadDn($request);

        return $dn !== null
            ? $this->postRead($dn, $controls, $token)
            : null;
    }

    public function preRead(
        Dn $dn,
        ControlBag $controls,
        TokenInterface $token,
    ): ?PreReadResponseControl {
        $entry = $this->readEntry(
            Control::OID_PRE_READ,
            $dn,
            $controls,
            $token,
        );

        return $entry !== null
            ? new PreReadResponseControl($entry)
            : null;
    }

    public function postRead(
        Dn $dn,
        ControlBag $controls,
        TokenInterface $token,
    ): ?PostReadResponseControl {
        $entry = $this->readEntry(
            Control::OID_POST_READ,
            $dn,
            $controls,
            $token,
        );

        return $entry !== null
            ? new PostReadResponseControl($entry)
            : null;
    }

    private function readEntry(
        string $oid,
        Dn $dn,
        ControlBag $controls,
        TokenInterface $token,
    ): ?Entry {
        $control = $controls->get($oid);

        if (!$control instanceof ReadEntryControl) {
            return null;
        }

        $entry = $this->backend->get($dn);

        if ($entry === null) {
            return null;
        }

        // Stripped before selection, so naming an unreadable attribute cannot pull it into the response. Entry-level
        // visibility is settled by the write authorization that precedes this, so only attribute rules apply.
        $readable = $this->accessControl->stripUnreadableAttributes(
            $token,
            $entry,
        );

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

    private function preReadDn(Request\RequestInterface $request): ?Dn
    {
        return match (true) {
            $request instanceof Request\DeleteRequest,
            $request instanceof Request\ModifyRequest,
            $request instanceof Request\ModifyDnRequest => $request->getDn(),
            default => null,
        };
    }

    private function postReadDn(Request\RequestInterface $request): ?Dn
    {
        return match (true) {
            $request instanceof Request\AddRequest => $request->getEntry()->getDn(),
            $request instanceof Request\ModifyRequest => $request->getDn(),
            $request instanceof Request\ModifyDnRequest => $this->newDnFor($request),
            default => null,
        };
    }

    /**
     * Resulting DN of a ModifyDN, mirroring the backend move semantics (new RDN under the new or existing parent).
     */
    private function newDnFor(Request\ModifyDnRequest $request): Dn
    {
        $parent = $request->getNewParentDn() ?? $request->getDn()->getParent();

        if ($parent === null) {
            return new Dn($request->getNewRdn()->toString());
        }

        return new Dn($request->getNewRdn()->toString() . ',' . $parent->toString());
    }
}
