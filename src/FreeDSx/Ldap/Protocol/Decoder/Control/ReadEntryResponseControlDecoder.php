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

namespace FreeDSx\Ldap\Protocol\Decoder\Control;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Control\ReadEntry\ReadEntryResponseControl;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

/**
 * Decodes a pre-read or post-read response control and the entry it carries (RFC 4527 3.1 and 3.2).
 *
 * @extends EncodedValueControlDecoder<ReadEntryResponseControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ReadEntryResponseControlDecoder extends EncodedValueControlDecoder
{
    /**
     * @param class-string<ReadEntryResponseControl> $controlClass the pre-read or post-read response control to build.
     */
    public function __construct(private string $controlClass) {}

    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): ReadEntryResponseControl {
        return new $this->controlClass(SearchResultEntry::fromAsn1($value)->getEntry());
    }
}
