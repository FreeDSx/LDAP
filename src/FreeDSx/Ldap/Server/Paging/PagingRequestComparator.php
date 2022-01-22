<?php

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
 * This determines "equality" of one paging request with another.
 *
 * Per RFC 2696:
 *
 * When the client wants to retrieve more entries for the result set, it MUST
 * send to the server a searchRequest with all values identical to the
 * initial request with the exception of the messageID, the cookie, and
 * optionally a modified pageSize. The cookie MUST be the octet string
 * on the last searchResultDone response returned by the server.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PagingRequestComparator
{
    /**
     * @var LdapEncoder
     */
    private $encoder;

    public function __construct(LdapEncoder $encoder = null)
    {
        $this->encoder = $encoder ?? new LdapEncoder();
    }

    /**
     * Compares the old paging request with the new request to determine if it is valid.
     *
     * @param PagingRequest $oldPagingRequest The previous paging request.
     * @param PagingRequest $newPagingRequest The paging request that was received.
     * @return bool
     */
    public function compare(
        PagingRequest $oldPagingRequest,
        PagingRequest $newPagingRequest
    ): bool {
        if ($oldPagingRequest->getNextCookie() !== $newPagingRequest->getCookie()) {
            return false;
        }

        $oldSearch = $oldPagingRequest->getSearchRequest();
        $newSearch = $newPagingRequest->getSearchRequest();

        return $newPagingRequest->isCritical() === $oldPagingRequest->isCritical()
            && $oldSearch->getAttributesOnly() === $newSearch->getAttributesOnly()
            && $oldSearch->getDereferenceAliases() === $newSearch->getDereferenceAliases()
            && $oldSearch->getScope() === $newSearch->getScope()
            && $oldSearch->getTimeLimit() === $newSearch->getTimeLimit()
            && $oldSearch->getSizeLimit() === $newSearch->getSizeLimit()
            && (string)$oldSearch->getBaseDn() === (string)$newSearch->getBaseDn()
            && $oldSearch->getFilter()->toString() === $newSearch->getFilter()->toString()
            && $this->attributesMatch($oldSearch->getAttributes(), $newSearch->getAttributes())
            && $this->controlsMatch($newPagingRequest->controls(), $oldPagingRequest->controls());
    }

    /**
     * @param Attribute[] $oldAttrs
     * @param Attribute[] $newAttrs
     * @return bool
     */
    private function attributesMatch(
        array $oldAttrs,
        array $newAttrs
    ): bool {
        if (count($oldAttrs) !== count($newAttrs)) {
            return false;
        }

        // This works by removing each attribute from their respective arrays as a match is found.
        // By the end, each array should be empty. We check that below.
        foreach ($oldAttrs as $iN => $oldAttr) {
            foreach ($newAttrs as $iO => $newAttr) {
                if ($newAttr->equals($oldAttr)) {
                    unset($newAttrs[$iO]);
                    unset($oldAttrs[$iN]);
                    continue 2;
                }
            }
        }

        return empty($newAttrs)
            && empty($oldAttrs);
    }

    /**
     * This is a somewhat crude way to determine that two sets of controls are "equal". It does the following:
     *
     *   1. Sorts the controls based on their type.
     *   2. Encodes the controls to their string value.
     *   3. Compares the collections encoded value to see if they match.
     *
     * If the encoded values of the two collections are the same, then they are considered "equal".
     *
     * @param ControlBag $newControls
     * @param ControlBag $oldControls
     * @return bool
     */
    private function controlsMatch(
        ControlBag $newControls,
        ControlBag $oldControls
    ): bool {
        if ($oldControls->count() !== $newControls->count()) {
            return false;
        }

        // Short circuit this...nothing to check. Only a paging control.
        if (empty($oldControls) && empty($newControls)) {
            return true;
        }

        $oldControls = $oldControls->toArray();
        $newControls = $newControls->toArray();

        // Sort both arrays, so they are ordered the same, then encode to a string and compare.
        usort($oldControls, function (Control $a, Control $b) {
            return $a->getTypeOid() <=> $b->getTypeOid();
        });
        usort($newControls, function (Control $a, Control $b) {
            return $a->getTypeOid() <=> $b->getTypeOid();
        });

        $oldEncoded = array_map(function (Control $control) {
            return $this->encoder->encode($control->toAsn1());
        }, $oldControls);
        $newEncoded = array_map(function (Control $control) {
            return $this->encoder->encode($control->toAsn1());
        }, $newControls);

        return implode('', $oldEncoded) === implode('', $newEncoded);
    }
}
