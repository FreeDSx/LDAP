<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\Exception\ConnectionException;
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

/**
 * Logic for handling referrals.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientReferralHandler implements ResponseHandlerInterface
{
    /**
     * @var array
     */
    protected $options = [];

    /**
     * {@inheritDoc}
     */
    public function handleResponse(LdapMessageRequest $messageTo, LdapMessageResponse $messageFrom, ClientQueue $queue, array $options): ?LdapMessageResponse
    {
        $this->options = $options;
        $result = $messageFrom->getResponse();
        switch ($this->options['referral']) {
            case 'throw':
                $message = $result instanceof LdapResult ? $result->getDiagnosticMessage() : 'Referral response encountered.';
                $referrals = $result instanceof LdapResult ? $result->getReferrals() : [];

                throw new ReferralException($message, ...$referrals);
                break;
            case 'follow':
                return $this->followReferral($messageTo, $messageFrom);
                break;
            default:
                throw new RuntimeException(sprintf(
                    'The referral option "%s" is invalid.',
                    $this->options['referral']
                ));
        }
    }

    protected function followReferral(LdapMessageRequest $messageTo, LdapMessageResponse $messageFrom): ?LdapMessageResponse
    {
        $referralChaser = $this->options['referral_chaser'];
        if (!($referralChaser === null || $referralChaser instanceof ReferralChaserInterface)) {
            throw new RuntimeException(sprintf(
                'The referral_chaser must implement "%s" or be null.',
                ReferralChaserInterface::class
            ));
        }
        if (!$messageFrom->getResponse() instanceof LdapResult || \count($messageFrom->getResponse()->getReferrals()) === 0) {
            throw new OperationException(
                'Encountered a referral request, but no referrals were supplied.',
                ResultCode::REFERRAL
            );
        }

        # Initialize a referral context to track the referrals we have already visited as well as count.
        if (!isset($this->options['_referral_context'])) {
            $this->options['_referral_context'] = new ReferralContext();
        }

        foreach ($messageFrom->getResponse()->getReferrals() as $referral) {
            # We must skip referrals we have already visited to avoid a referral loop
            if ($this->options['_referral_context']->hasReferral($referral)) {
                continue;
            }

            $this->options['_referral_context']->addReferral($referral);
            if ($this->options['_referral_context']->count() > $this->options['referral_limit']) {
                throw new OperationException(sprintf(
                    'The referral limit of %s has been reached.',
                    $this->options['referral_limit']
                ));
            }

            $bind = null;
            try {
                # @todo Remove the bind parameter from the interface in a future release.
                if ($referralChaser !== null) {
                    $bind = $referralChaser->chase($messageTo, $referral, null);
                }
            } catch (SkipReferralException $e) {
                continue;
            }
            $options = $this->options;
            $options['servers'] = $referral->getHost() !== null ? [$referral->getHost()] : [];
            $options['port'] = $referral->getPort() ?? 389;
            $options['use_ssl'] = $referral->getUseSsl();

            # Each referral could potentially modify different aspects of the request, depending on the URL. Clone it
            # here, merge the options, then use that request to send to LDAP. This makes sure we don't accidentally mix
            # options from different referrals.
            $request = clone $messageTo->getRequest();
            $this->mergeReferralOptions($request, $referral);

            try {
                $client = $referralChaser !== null ? $referralChaser->client($options) : new LdapClient($options);

                # If we have a referral on a bind request, then do not bind initially.
                #
                # It's not clear that this should even be allowed, though RFC 4511 makes no indication that referrals
                # should not be followed on a bind request. The problem is that while we bind on a different server,
                # this client continues on with a different bind state, which seems confusing / problematic.
                if ($bind !== null && !$messageTo->getRequest() instanceof BindRequest) {
                    $client->send($bind);
                }

                $response = $client->send($messageTo->getRequest(), ...$messageTo->controls());

                return $response;
                # Skip referrals that fail due to connection issues and not other issues
            } catch (ConnectionException $e) {
                continue;
                # If the referral encountered other referrals but exhausted them, continue to the next one.
            } catch (OperationException $e) {
                if ($e->getCode() === ResultCode::REFERRAL) {
                    continue;
                }
                # Other operation errors should bubble up, so throw it
                throw  $e;
            } catch (\Throwable $e) {
                throw $e;
            }
        }

        # If we have exhausted all referrals consider it an operation exception.
        throw new OperationException(sprintf(
            'All referral attempts have been exhausted. %s',
            $messageFrom->getResponse()->getDiagnosticMessage()
        ), ResultCode::REFERRAL);
    }

    /**
     * @param RequestInterface $request
     * @param LdapUrl $referral
     */
    protected function mergeReferralOptions(RequestInterface $request, LdapUrl $referral): void
    {
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
}
