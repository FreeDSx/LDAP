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

namespace FreeDSx\Ldap\Server\Backend\Auth;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Socket\Tls\Certificate;

use function array_map;
use function array_reverse;
use function implode;
use function is_array;

/**
 * Default EXTERNAL mapper.
 *
 * The certificate subject DN, resolved as-is via the identity resolver chain.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SubjectDnCredentialMapper implements ExternalCredentialMapperInterface
{
    public function map(Certificate $certificate): ?AuthzId
    {
        $components = [];
        foreach ($certificate->getSubject() as $attribute => $value) {
            $components = [
                ...$components,
                ...$this->escapeComponents($attribute, $value),
            ];
        }

        if ($components === []) {
            return null;
        }

        // X.509 subjects are ordered most-general first; an LDAP DN is most-specific first.
        return AuthzId::fromDn(new Dn(implode(
            ',',
            array_reverse($components),
        )));
    }

    /**
     * The escaped "attr=value" RDN component(s) for one subject attribute (expanding multi-valued attributes, e.g. DC).
     *
     * @param string|list<string> $value
     *
     * @return list<string>
     */
    private function escapeComponents(
        string $attribute,
        string|array $value,
    ): array {
        return array_map(
            fn(string $single): string => $attribute . '=' . Rdn::escape($single),
            is_array($value) ? $value : [$value],
        );
    }
}
