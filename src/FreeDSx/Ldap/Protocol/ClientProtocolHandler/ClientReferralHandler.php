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

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\FilterParseException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Exception\SkipReferralException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\DnRequestInterface;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\ReferralContext;
use FreeDSx\Ldap\ReferralChaserInterface;
use FreeDSx\Ldap\Search\Filters;
use function count;

/**
 * Logic for handling referrals.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientReferralHandler implements ResponseHandlerInterface
{
    private ClientOptions $options;

    private ?ReferralContext $referralContext = null;

    /**
     * {@inheritDoc}
     *
     * @throws OperationException
     * @throws ReferralException
     */
    public function handleResponse(
        LdapMessageRequest $messageTo,
        LdapMessageResponse $messageFrom,
        ClientQueue $queue,
        ClientOptions $options
    ): ?LdapMessageResponse {
        $this->options = $options;
        $result = $messageFrom->getResponse();
        switch ($this->options->getReferral()) {
            case 'throw':
                $message = $result instanceof LdapResult
                    ? $result->getDiagnosticMessage()
                    : 'Referral response encountered.';
                $referrals = $result instanceof LdapResult
                    ? $result->getReferrals()
                    : [];

                throw new ReferralException($message, ...$referrals);
            case 'follow':
                return $this->followReferral(
                    $messageTo,
                    $messageFrom
                );
            default:
                throw new RuntimeException(sprintf(
                    'The referral option "%s" is invalid.',
                    $this->options->getReferral()
                ));
        }
    }

    /**
     * @throws OperationException
     * @throws SkipReferralException
     * @throws FilterParseException
     */
    private function followReferral(
        LdapMessageRequest $messageTo,
        LdapMessageResponse $messageFrom
    ): ?LdapMessageResponse {
        $referralChaser = $this->getReferralChaser();

        $response = $messageFrom->getResponse();
        $referrals = $this->getReferralsFromResponse($messageFrom);
        if (!$response instanceof LdapResult || count($referrals) === 0) {
            throw new OperationException(
                'Encountered a referral request, but no referrals were supplied.',
                ResultCode::REFERRAL
            );
        }

        $referralContext = $this->getReferralContext();

        foreach ($referrals as $referral) {
            # We must skip referrals we have already visited to avoid a referral loop
            if ($referralContext->hasReferral($referral)) {
                continue;
            }

            $referralContext->addReferral($referral);
            if ($referralContext->count() > $this->options->getReferralLimit()) {
                throw new OperationException(sprintf(
                    'The referral limit of %s has been reached.',
                    $this->options->getReferralLimit()
                ));
            }

            $bind = null;
            try {
                # @todo Remove the bind parameter from the interface in a future release.
                $bind = $referralChaser->chase(
                    request: $messageTo,
                    referral: $referral,
                    bind: null,
                );
            } catch (SkipReferralException) {
                continue;
            }
            $options = clone $this->options;
            $options->setServers(
                $referral->getHost() !== null
                    ? [$referral->getHost()]
                    : []
            );
            $options->setPort($referral->getPort() ?? 389);
            $options->setUseSsl($referral->getUseSsl());

            # Each referral could potentially modify different aspects of the request, depending on the URL. Clone it
            # here, merge the options, then use that request to send to LDAP. This makes sure we don't accidentally mix
            # options from different referrals.
            $request = clone $messageTo->getRequest();
            $this->mergeReferralOptions($request, $referral);

            try {
                $client = $referralChaser->client($options);

                # If we have a referral on a bind request, then do not bind initially.
                #
                # It's not clear that this should even be allowed, though RFC 4511 makes no indication that referrals
                # should not be followed on a bind request. The problem is that while we bind on a different server,
                # this client continues on with a different bind state, which seems confusing / problematic.
                if ($bind !== null && !$messageTo->getRequest() instanceof BindRequest) {
                    $client->send($bind);
                }

                return $client->send(
                    $messageTo->getRequest(),
                    ...$messageTo->controls()->toArray()
                );
                # Skip referrals that fail due to connection issues and not other issues
            } catch (ConnectionException) {
                continue;
                # If the referral encountered other referrals but exhausted them, continue to the next one.
            } catch (OperationException $e) {
                if ($e->getCode() === ResultCode::REFERRAL) {
                    continue;
                }
                # Other operation errors should bubble up, so throw it
                throw  $e;
            }
        }

        # If we have exhausted all referrals consider it an operation exception.
        throw new OperationException(sprintf(
            'All referral attempts have been exhausted. %s',
            $response->getDiagnosticMessage()
        ), ResultCode::REFERRAL);
    }

    /**
     * @throws FilterParseException
     */
    private function mergeReferralOptions(
        RequestInterface $request,
        LdapUrl $referral
    ): void {
        if ($referral->getDn() !== null && $request instanceof SearchRequest) {
            $request->setBaseDn($referral->getDn());
        } elseif ($referral->getDn() !== null && $request instanceof DnRequestInterface) {
            $request->setDn($referral->getDn());
        }

        if ($referral->getScope() !== null && $request instanceof SearchRequest) {
            if ($referral->getScope() === LdapUrl::SCOPE_SUB) {
                $request->setScope(SearchRequest::SCOPE_WHOLE_SUBTREE);
            } elseif ($referral->getScope() === LdapUrl::SCOPE_BASE) {
                $request->setScope(SearchRequest::SCOPE_SINGLE_LEVEL);
            } else {
                $request->setScope(SearchRequest::SCOPE_BASE_OBJECT);
            }
        }

        if ($referral->getFilter() !== null && $request instanceof SearchRequest) {
            $request->setFilter(Filters::raw($referral->getFilter()));
        }
    }

    /**
     * @return LdapUrl[]
     */
    private function getReferralsFromResponse(LdapMessageResponse $messageFrom): array
    {
        $response = $messageFrom->getResponse();

        return !$response instanceof LdapResult
            ? []
            : $response->getReferrals();
    }

    private function getReferralChaser(): ReferralChaserInterface
    {
        return $this->options->getReferralChaser() ?? throw new RuntimeException(
            'No referral chaser was provided.'
        );
    }

    private function getReferralContext(): ReferralContext
    {
        # Initialize a referral context to track the referrals we have already visited as well as count.
        if ($this->referralContext === null) {
            $this->referralContext = new ReferralContext();
        }

        return $this->referralContext;
    }
}
