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

namespace FreeDSx\Ldap\Ldif;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Operation\Request\RequestInterface;

use function array_values;

/**
 * One parsed LDIF record, with the controls RFC 2849 allows a change record to carry.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LdifChangeRecord
{
    /**
     * @var list<Control>
     */
    public array $controls;

    public function __construct(
        public RequestInterface $request,
        Control ...$controls,
    ) {
        $this->controls = array_values($controls);
    }
}
