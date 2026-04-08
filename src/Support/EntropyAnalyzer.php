<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Support;

final readonly class EntropyAnalyzer
{
    /**
     * Compute Shannon entropy for a string.
     *
     * -Σ p(x) * log2(p(x)) over character frequencies.
     */
    public function entropy(string $value): float
    {
        if ($value === '') {
            return 0.0;
        }

        $length = strlen($value);
        $frequencies = array_count_values(str_split($value));
        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $probability = $count / $length;
            $entropy -= $probability * log($probability, 2);
        }

        return $entropy;
    }

    /**
     * Whether the value meets the given entropy threshold.
     */
    public function meetsThreshold(string $value, float $threshold): bool
    {
        return $this->entropy($value) >= $threshold;
    }
}
