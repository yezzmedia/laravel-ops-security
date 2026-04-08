<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Support;

use YezzMedia\Foundation\Data\SecurityRequestDefinition;

class SecurityPayloadSanitizer
{
    /**
     * @param  array<string, mixed>  $payload
     * @return array<string, scalar|null>
     */
    public function preview(SecurityRequestDefinition $definition, array $payload): array
    {
        $preview = [];

        foreach ($definition->allowedPreviewFields as $field) {
            $value = $payload[$field] ?? null;

            if (in_array($field, $definition->maskedFields, true)) {
                $preview[$field] = $this->mask($value);

                continue;
            }

            $preview[$field] = $this->normalize($value);
        }

        return $preview;
    }

    private function mask(mixed $value): string
    {
        if ($value === null || $value === '') {
            return 'masked';
        }

        $normalized = (string) $this->normalize($value);
        $suffix = substr($normalized, -4);

        return '***'.$suffix;
    }

    private function normalize(mixed $value): string|int|float|bool|null
    {
        if (is_string($value) || is_int($value) || is_float($value) || is_bool($value) || $value === null) {
            return $value;
        }

        if (is_array($value)) {
            return json_encode($value, JSON_THROW_ON_ERROR);
        }

        return (string) $value;
    }
}
