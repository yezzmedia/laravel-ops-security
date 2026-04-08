<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Enums;

enum SecurityPostureStatus: string
{
    case Healthy = 'healthy';
    case Warning = 'warning';
    case Critical = 'critical';
    case Unknown = 'unknown';

    public function label(): string
    {
        return match ($this) {
            self::Healthy => 'Healthy',
            self::Warning => 'Warning',
            self::Critical => 'Critical',
            self::Unknown => 'Unknown',
        };
    }

    public function color(): string
    {
        return match ($this) {
            self::Healthy => 'success',
            self::Warning => 'warning',
            self::Critical => 'danger',
            self::Unknown => 'gray',
        };
    }

    public function icon(): string
    {
        return match ($this) {
            self::Healthy => 'heroicon-o-check-circle',
            self::Warning => 'heroicon-o-exclamation-triangle',
            self::Critical => 'heroicon-o-x-circle',
            self::Unknown => 'heroicon-o-question-mark-circle',
        };
    }

    /**
     * Return the more severe of two statuses.
     *
     * Unknown is treated as Warning during aggregation.
     */
    public function worst(self $other): self
    {
        $priority = static fn (self $s): int => match ($s) {
            self::Healthy => 0,
            self::Unknown => 1,
            self::Warning => 1,
            self::Critical => 2,
        };

        $result = $priority($this) >= $priority($other) ? $this : $other;

        // Normalize Unknown to Warning in aggregation output
        if ($result === self::Unknown) {
            return self::Warning;
        }

        return $result;
    }

    /**
     * Return the worst status from an array.
     */
    public static function worstOf(array $statuses): self
    {
        if ($statuses === []) {
            return self::Unknown;
        }

        $result = self::Healthy;

        foreach ($statuses as $status) {
            $result = $result->worst($status);
        }

        return $result;
    }
}
