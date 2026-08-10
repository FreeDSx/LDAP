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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;

/**
 * Handles RootDSE based search requests.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerRootDseHandler implements ServerProtocolHandlerInterface
{
    /**
     * RFC 3673 §3 — return all operational attributes via the "+" attribute description.
     */
    private const FEATURE_OID_ALL_OPERATIONAL_ATTRS = '1.3.6.1.4.1.4203.1.5.1';

    /**
     * RFC 4526 — absolute True ("(&)") and False ("(|)") filters.
     */
    private const FEATURE_OID_ABSOLUTE_TRUE_FALSE_FILTERS = '1.3.6.1.4.1.4203.1.5.3';

    public function __construct(
        private readonly ServerOptions $options,
        private readonly EntryStorageInterface $storage,
        private readonly GeneratedEntryResponder $responder,
        private readonly bool $supportsSync = false,
    ) {}

    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        $entry = Entry::fromArray('', [
            // Clients discover the Root DSE with the "(objectClass=*)" filter of RFC 4512 section 5.1.
            'objectClass' => [ObjectClassOid::NAME_TOP],
            'namingContexts' => array_map(
                fn(Dn $dn): string => $dn->toString(),
                $this->storage->namingContexts(),
            ),
            'subschemaSubentry' => [$this->options->getSubschemaEntry()->toString()],
            'supportedControl' => [
                Control::OID_PAGING,
                Control::OID_SORTING,
                Control::OID_RELAX_RULES,
                Control::OID_PROXY_AUTHORIZATION,
                Control::OID_MANAGE_DSA_IT,
                Control::OID_ASSERTION,
                Control::OID_PRE_READ,
                Control::OID_POST_READ,
                Control::OID_SUBTREE_DELETE,
                Control::OID_SUBENTRIES,
                Control::OID_PWD_POLICY,
            ],
            'supportedExtension' => [
                ExtendedRequest::OID_WHOAMI,
                ExtendedRequest::OID_PWD_MODIFY,
                ExtendedRequest::OID_CANCEL,
            ],
            'supportedFeatures' => [
                self::FEATURE_OID_ALL_OPERATIONAL_ATTRS,
                self::FEATURE_OID_ABSOLUTE_TRUE_FALSE_FILTERS,
            ],
            'supportedLDAPVersion' => ['3'],
            'vendorName' => $this->options->getDseVendorName(),
        ]);
        if ($this->supportsSync) {
            $entry->add(
                'supportedControl',
                Control::OID_SYNC_REQUEST,
            );
            $entry->add(
                'supportedExtension',
                ExtendedRequest::OID_PPOLICY_STATE_FORWARD,
            );
        }
        if ($this->options->getNetworkConfig()->getSslCert()) {
            $entry->add(
                'supportedExtension',
                ExtendedRequest::OID_START_TLS,
            );
        }
        if ($this->options->getDseVendorVersion()) {
            $entry->set('vendorVersion', (string) $this->options->getDseVendorVersion());
        }
        if (!empty($this->options->getSaslMechanisms())) {
            $entry->set('supportedSaslMechanisms', ...$this->options->getSaslMechanisms());
        }
        if ($this->options->getDseAltServer()) {
            $entry->set('altServer', (string) $this->options->getDseAltServer());
        }

        $entry = $this->responder->readable(
            $entry,
            $token,
        );

        // Stripping and matching both precede attribute selection, since selecting must not change what matched.
        if (!$this->responder->matches($message, $entry)) {
            return $this->responder->reply(
                $message,
                null,
            );
        }

        /** @var SearchRequest $request */
        $request = $message->getRequest();

        // Every attribute here is operational, so "+" is the only wildcard that selects them (RFC 4512 section 5.1).
        $projection = AttributeProjection::forRequest(
            $request->getAttributes(),
            $request->getAttributesOnly(),
            $this->options->getSchema(),
        );

        return $this->responder->reply(
            $message,
            $projection->project($entry),
        );
    }
}
