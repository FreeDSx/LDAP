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

namespace Tests\Unit\FreeDSx\Ldap\Server\Initialization;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Initialization\AdvisoryInterface;
use FreeDSx\Ldap\Server\Initialization\InitializationWarning;
use FreeDSx\Ldap\Server\Initialization\RequirementInterface;
use FreeDSx\Ldap\Server\Initialization\ServerInitialization;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class ServerInitializationTest extends TestCase
{
    private RequirementInterface&MockObject $requirement;

    private AdvisoryInterface&MockObject $advisory;

    private RecordingLogger $logger;

    private ServerInitialization $subject;

    protected function setUp(): void
    {
        $this->requirement = $this->createMock(RequirementInterface::class);
        $this->advisory = $this->createMock(AdvisoryInterface::class);
        $this->logger = new RecordingLogger();

        $this->subject = new ServerInitialization(
            [$this->requirement],
            [$this->advisory],
            new EventLogger(
                $this->logger,
                EventLogPolicy::default(),
            ),
        );
    }

    public function test_starting_records_each_warning_once_the_requirements_are_met(): void
    {
        $this->requirement
            ->expects(self::once())
            ->method('assertMet');
        $this->advisory
            ->method('warnings')
            ->willReturn([
                InitializationWarning::concurrencyLimited(
                    ConcurrencyLimitReason::OpenFileLimit,
                    ['open_file_limit' => 256],
                ),
            ]);

        $this->subject->start();

        self::assertSame(
            [
                [
                    LogLevel::WARNING,
                    [
                        EventContext::REASON => ConcurrencyLimitReason::OpenFileLimit->value,
                        'open_file_limit' => 256,
                        EventContext::EVENT => ServerEvent::ConcurrencyLimited->value,
                    ],
                ],
            ],
            array_map(
                static fn(array $record): array => [
                    $record['level'],
                    $record['context'],
                ],
                $this->logger->records,
            ),
        );
    }

    public function test_a_requirement_not_met_refuses_the_start_before_any_warning_is_recorded(): void
    {
        $this->requirement
            ->method('assertMet')
            ->willThrowException(new RuntimeException('The configuration is refused.'));
        $this->advisory
            ->expects(self::never())
            ->method('warnings');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The configuration is refused.');

        $this->subject->start();
    }

    public function test_a_reload_checks_the_requirements_without_recording_warnings(): void
    {
        $this->requirement
            ->expects(self::once())
            ->method('assertMet');
        $this->advisory
            ->expects(self::never())
            ->method('warnings');

        $this->subject->reload();
    }

    public function test_a_requirement_not_met_refuses_the_reload(): void
    {
        $this->requirement
            ->method('assertMet')
            ->willThrowException(new RuntimeException('The configuration is refused.'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The configuration is refused.');

        $this->subject->reload();
    }
}
