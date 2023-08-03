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

namespace spec\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use Closure;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use PhpParser\Node\Arg;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use spec\FreeDSx\Ldap\TestFactoryTrait;

class RequestCancelerSpec extends ObjectBehavior
{
    public function it_should_return_the_cancel_response(ClientQueue $queue): void
    {
        $this->beConstructedWith($queue);

        $cancelResponse = new ExtendedResponse(new LdapResult(ResultCode::CANCELED));
        $queue
            ->getMessage()
            ->willReturn(
                new LdapMessageResponse(1, new SearchResultEntry(Entry::create(''))),
                new LdapMessageResponse(1, new SearchResultReference()),
                new LdapMessageResponse(2, $cancelResponse),
            )
        ;
        $queue
            ->generateId()
            ->willReturn(2)
        ;

        $queue
            ->sendMessage(Argument::that(
                fn(LdapMessageRequest $request) =>
                    $request->getRequest() instanceof CancelRequest
            ))
            ->shouldBeCalledOnce();

        $this->cancel(1)
            ->shouldBe($cancelResponse);
    }

    public function it_should_keep_processing_on_the_continue_strategy(
        ClientQueue $queue,
        MockCancelResponseProcessor $mockResponseProcessor,
    ): void {
        $this->beConstructedWith(
            $queue,
            SearchRequest::CANCEL_CONTINUE,
            Closure::fromCallable($mockResponseProcessor->getWrappedObject()),
        );

        $queue
            ->sendMessage(Argument::any())
            ->willReturn($queue);
        $queue
            ->getMessage()
            ->willReturn(
                new LdapMessageResponse(1, new SearchResultEntry(Entry::create(''))),
                new LdapMessageResponse(1, new SearchResultReference()),
                new LdapMessageResponse(2, new ExtendedResponse(new LdapResult(ResultCode::CANCELED))),
            )
        ;
        $queue
            ->generateId()
            ->willReturn(2)
        ;

        $this->cancel(1);

        $mockResponseProcessor
            ->__invoke(Argument::any())
            ->shouldHaveBeenCalledTimes(2);
    }

    public function it_should_throw_an_operation_error_if_the_cancel_result_code_was_not_success(ClientQueue $queue): void
    {
        $this->beConstructedWith($queue);

        $cancelResponse = new ExtendedResponse(new LdapResult(
            ResultCode::TOO_LATE,
            '',
            'Fail'
        ));
        $queue
            ->getMessage()
            ->willReturn(new LdapMessageResponse(2, $cancelResponse))
        ;
        $queue
            ->generateId()
            ->willReturn(2)
        ;

        $queue
            ->sendMessage(Argument::any())
            ->willReturn($queue);

        $this
            ->shouldThrow(new OperationException(
                $cancelResponse->getDiagnosticMessage(),
                $cancelResponse->getResultCode()
            ))
            ->during('cancel', [1])
        ;
    }
}
