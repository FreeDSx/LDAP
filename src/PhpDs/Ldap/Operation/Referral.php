<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Operation;

/**
 * Represents a referral.
 *
 * @todo Parse the LDAP URL (RFC 4516) pieces. Making this a class for ease of implementation later.
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Referral
{
    /**
     * @var string
     */
    protected $referral;

    /**
     * @param string $referral
     */
    public function __construct(string $referral)
    {
        $this->referral = $referral;
    }

    /**
     * @return string
     */
    public function toString() : string
    {
        return $this->referral;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->referral;
    }
}
