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

namespace FreeDSx\Ldap\Server\Paging;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Protocol\LdapEncoder;

/**
 * Fingerprints the parts of a paged search that RFC 2696 §3 requires every page to repeat.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PagingRequestFingerprint
{
    public function __construct(private LdapEncoder $encoder = new LdapEncoder()) {}

    public function of(PagingRequest $request): string
    {
        $search = $request->getSearchRequest();

        return hash(
            'sha256',
            serialize([
                $request->isCritical(),
                $search->getAttributesOnly(),
                $search->getDereferenceAliases(),
                $search->getScope(),
                $search->getTimeLimit(),
                $search->getSizeLimit(),
                (string) $search->getBaseDn(),
                // Encoded, since the string form cannot represent every filter or tell every two apart.
                $this->encoder->encode($search->getFilter()->toAsn1()),
                $this->attributesOf($search->getAttributes()),
                $this->controlsOf($request->controls()),
            ]),
            true,
        );
    }

    /**
     * Neither the order of the attributes nor the case of their names and options changes what is asked for.
     *
     * @param Attribute[] $attributes
     * @return list<string>
     */
    private function attributesOf(array $attributes): array
    {
        $described = array_map(
            static fn(Attribute $attribute): string => strtolower($attribute->getName())
                . ';'
                . $attribute->getOptions()->toString(sortedlc: true),
            array_values($attributes),
        );
        sort($described);

        return $described;
    }

    /**
     * Encoded so a control's value counts too, and sorted since their order carries no meaning.
     *
     * @return list<string>
     */
    private function controlsOf(ControlBag $controls): array
    {
        $encoded = array_map(
            fn(Control $control): string => $this->encoder->encode($control->toAsn1()),
            array_values($controls->toArray()),
        );
        sort($encoded);

        return $encoded;
    }
}
