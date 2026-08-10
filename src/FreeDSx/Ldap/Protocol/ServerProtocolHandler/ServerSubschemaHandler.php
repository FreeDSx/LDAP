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
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;

/**
 * Returns the full RFC 4512 subschema entry from the active schema registry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerSubschemaHandler implements ServerProtocolHandlerInterface
{
    public function __construct(
        private readonly ServerOptions $options,
        private readonly GeneratedEntryResponder $responder,
    ) {}

    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        $schemaDn = $this->options->getSubschemaEntry();
        $rdn = $schemaDn->getRdn();
        $schema = $this->options->getSchema();

        $entry = Entry::fromArray(
            $schemaDn->toString(),
            array_filter([
                AttributeTypeOid::NAME_OBJECT_CLASS => [
                    ObjectClassOid::NAME_TOP,
                    ObjectClassOid::NAME_SUBSCHEMA,
                ],
                $rdn->getName() => [$rdn->getValue()],
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
                AttributeTypeOid::NAME_MATCHING_RULE_USE => $this->buildMatchingRuleUse($schema),
            ]),
        );

        // The schema definitions are operational, so a client that does not ask for them gets the naming attributes only.
        return $this->responder->respondWith(
            $message,
            $entry,
            $token,
        );
    }

    /**
     * @return list<string>
     */
    private function buildMatchingRuleUse(Schema $schema): array
    {
        $ruleToAttrs = [];
        foreach ($schema->getAttributeTypes() as $attrType) {
            $name = $attrType->names[0] ?? $attrType->oid;

            if ($attrType->equalityOid !== null) {
                $ruleToAttrs[$attrType->equalityOid][] = $name;
            }

            if ($attrType->orderingOid !== null) {
                $ruleToAttrs[$attrType->orderingOid][] = $name;
            }

            if ($attrType->substringOid !== null) {
                $ruleToAttrs[$attrType->substringOid][] = $name;
            }
        }

        $use = [];
        foreach ($ruleToAttrs as $ruleOid => $attrNames) {
            $rule = $schema->getMatchingRule($ruleOid);
            if ($rule === null) {
                continue;
            }

            $use[] = $rule->toMatchingRuleUseString($attrNames);
        }

        return $use;
    }
}
