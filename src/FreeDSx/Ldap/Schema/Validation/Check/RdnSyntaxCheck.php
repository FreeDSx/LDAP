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

namespace FreeDSx\Ldap\Schema\Validation\Check;

use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;

use function sprintf;

/**
 * RFC 4511 A.2: an RDN holding a value its type's syntax rejects is an invalid DN.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class RdnSyntaxCheck implements SchemaCheckInterface
{
    public function __construct(private AttributeSyntaxResolver $syntaxResolver) {}

    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        $dn = $write->entry->getDn();

        if (!$write->namesEntry() || $dn->isRootDse()) {
            return [];
        }

        foreach ($dn->getRdn()->getAll() as $component) {
            if ($this->syntaxResolver->conforms($component->getName(), Rdn::unescape($component->getValue()))) {
                continue;
            }

            return [
                new RuleViolation(
                    SchemaRule::AttributeSyntax,
                    ResultCode::INVALID_DN_SYNTAX,
                    sprintf(
                        'A value of attribute "%s" in the RDN does not conform to its syntax.',
                        $component->getName(),
                    ),
                ),
            ];
        }

        return [];
    }
}
