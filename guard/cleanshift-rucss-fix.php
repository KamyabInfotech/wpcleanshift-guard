<?php
/**
 * CleanShift: Disable WP Rocket SaaS features that don't work with AccelerateWP
 *
 * AccelerateWP (clsop) bundles WP Rocket but the SaaS-dependent features
 * (RUCSS, SaaS jobs) fail silently and spam the error log with
 * "cron event list could not be saved" every 60 seconds.
 *
 * This mu-plugin disables those broken features without affecting
 * the core caching functionality.
 */

// Disable Remove Unused CSS (SaaS-dependent)
if (!defined('ABSPATH')) {
    exit;
}

add_filter('rocket_rucss_enabled', '__return_false');

// Ensure caching files are generated locally
add_filter('do_rocket_generate_caching_files', '__return_true');
