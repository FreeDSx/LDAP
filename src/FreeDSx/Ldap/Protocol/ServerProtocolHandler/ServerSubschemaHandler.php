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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;
use FreeDSx\Ldap\Server\GeneratedEntry;
use FreeDSx\Ldap\Server\Subentry\SubtreeSpecification;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;

/**
 * Returns the full RFC 4512 subschema entry from the active schema registry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerSubschemaHandler implements ServerProtocolHandlerInterface
{
    public function __construct(
        private ServerOptions $options,
        private GeneratedEntryResponder $responder,
    ) {}

    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        $schemaDn = GeneratedEntry::Subschema->dn();
        $rdn = $schemaDn->getRdn();
        $schema = $this->options->getSchema();
        $changedAt = GeneralizedTime::format($this->options->getSchemaConfig()->getChangedAt());

        $entry = Entry::fromArray(
            $schemaDn->toString(),
            array_filter([
                // RFC 4512 2.4.2: an entry has one structural class, and 4.2 declares subschema auxiliary.
                AttributeTypeOid::NAME_OBJECT_CLASS => [
                    ObjectClassOid::NAME_TOP,
                    ObjectClassOid::NAME_SUBENTRY,
                    ObjectClassOid::NAME_SUBSCHEMA,
                ],
                AttributeTypeOid::NAME_STRUCTURAL_OBJECT_CLASS => [ObjectClassOid::NAME_SUBENTRY],
                $rdn->getName() => [$rdn->getValue()],
                // Satisfies subentry's MUST, and RFC 3672 reads the empty specification as the whole subtree.
                AttributeTypeOid::NAME_SUBTREE_SPECIFICATION => [(new SubtreeSpecification())->toString()],
                // Self-referential, so a client discovering schema never has to special-case this entry.
                AttributeTypeOid::NAME_SUBSCHEMA_SUBENTRY => [$schemaDn->toString()],
                // RFC 4512 4.2: lets a client caching the schema tell whether its copy is stale.
                AttributeTypeOid::NAME_CREATE_TIMESTAMP => [$changedAt],
                AttributeTypeOid::NAME_MODIFY_TIMESTAMP => [$changedAt],
                AttributeTypeOid::NAME_ATTRIBUTE_TYPES => array_map(
                    fn($at) => $at->toDescriptionString(),
                    $schema->getAttributeTypes(),
                ),
                AttributeTypeOid::NAME_OBJECT_CLASSES => array_map(
                    fn($oc) => $oc->toDescriptionString(),
                    $schema->getObjectClasses(),
                ),
                AttributeTypeOid::NAME_MATCHING_RULES => array_map(
                    fn($mr) => $mr->toDescriptionString(),
                    $schema->getMatchingRules(),
                ),
                AttributeTypeOid::NAME_LDAP_SYNTAXES => array_map(
                    fn($ls) => $ls->toDescriptionString(),
                    $schema->getLdapSyntaxes(),
                ),
                // Any recognized rule may be used with any type in an extensible match, which leaves no matchingRuleUse to publish.
            ]),
        );

        // The schema definitions are operational, so a client that does not ask for them gets the naming attributes only.
        return $this->responder->respondWith(
            $message,
            $entry,
            $token,
        );
    }
}
