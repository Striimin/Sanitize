<?php

namespace Striimin;

use Underscore\Underscore as _;

/**
 * Utility functions for sanitizing file names and other strings
 *
 * @author Peter Hillerström <peter.hillerstrom@striim.in>
 */
class Sanitize
{
    /**
     * Sanitize a filename
     *
     * - Converts the input to ASCII using UTF-8 transliteration
     * - Omits non-word and non-whitespace characters
     * - Replaces runs of non-word characters with dashes
     * - Enforces a maximum length
     * - Trims non-alphanumeric ends
     * - Adds the partial hash in order to always get a non-empty result
     *
     * @param string $filename Filename without slashes
     * @param $maxLength Maximum length of the output
     * @param int $hashLength Partial SHA-256 hash of the original $filename
     *
     * @throws InvalidArgumentException if $filename has slashes
     *
     * @return string with a length in the closed interval [$hashlength, $maxLength].
     */
    public static function filename($filename, $maxLength = 255, $hashLength = 7)
    {
        mb_regex_encoding('UTF-8');

        if (mb_ereg('/', $filename)) {
            throw \InvalidArgumentException('no paths please, just file names');
        }

        $hash = mb_substr(hash('sha256', $filename), 0, (int) $hashLength);

        list($base, $extension) = static::splitExtension($filename);
        $extension = mb_strtolower($extension);

        $sanitized = static::sanitize($base);
        $sanitized = static::maxLength($sanitized, (int) $maxLength - (($hashLength ? (int) $hashLength + 1 : 0) + mb_strlen($extension)));
        $sanitized = static::trimNonAlnumEnds($sanitized);

        // Add partial hash in order to prevent empty or duplicate filenames
        $sanitized = implode('', [implode('-', _::filter([$sanitized, $hash])), $extension]);

        return $sanitized;
    }

    /**
     * Slugify a string
     *
     * Simplified slugify that only passes in alphanumeric characters, and replaces runs of others with dashes.
     * Also only allows alphanumeric characters on start and end.
     * The result is usable as a part of DNS domain name.
     */
    public static function slugify($string, $maxLength = 255, $hashLength = 6)
    {
        mb_regex_encoding('UTF-8');

        $hash = mb_substr(hash('sha256', $string), 0, (int) $hashLength);

        $sanitized = static::sanitize($string);
        $sanitized = static::maxLength($sanitized, (int) $maxLength - ($hashLength ? (int) $hashLength + 1 : 0));
        $sanitized = static::trimNonAlnumEnds($sanitized);

        // Add partial hash in order to prevent empty or duplicate slugs
        $sanitized = implode('-', _::filter([$sanitized, $hash]));

        return $sanitized;
    }

    public static function sanitize($str)
    {
        mb_regex_encoding('UTF-8');

        // Transliterate non-ascii characters
        $sanitized = iconv('utf-8', 'ascii//TRANSLIT//IGNORE', $str);

        // Replace runs of whitespace, underscores and dashes with a dash
        $sanitized = mb_ereg_replace("[\s_-]+", '-', $sanitized);

        // Omit non-word and non-whitespace characters
        $sanitized = mb_ereg_replace("[^[:alnum:]\-_.]", '', $sanitized);

        // Replace runs of non-alphanumeric characters with dashes
        $sanitized = mb_ereg_replace("[^[:alnum:]]+", '-', $sanitized);

        return $sanitized;
    }

    public static function splitExtension($filename)
    {
        mb_regex_encoding('UTF-8');

        $re = "(.*?)((\.[[A-Z][a-z][0-9]]+)*)$";
        if ($filename && mb_ereg_search_init($filename, $re)) {
            $matches = mb_ereg_search_regs($re);
            return array_slice($matches, 1, 2);
        } else {
            return [$filename, ''];
        }
    }

    /**
     * Enforce max length
     */
    private static function maxLength($string, $maxLength)
    {
        return mb_substr($string, 0, max(0, (int) $maxLength), $encoding = 'UTF-8');
    }

    /**
     * Trim non-alphanumeric ends of a string
     */
    private static function trimNonAlnumEnds($string)
    {
        mb_regex_encoding('UTF-8');

        return mb_ereg_replace('(^[^[:alnum:]]+|[^[:alnum:]]$)', '', $string);
    }
}