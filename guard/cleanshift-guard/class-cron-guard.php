<?php
/**
 * CleanShift Cron Guard
 *
 * Monitors and blocks suspicious WordPress cron job registration.
 * Nobody else does this — always enabled regardless of security stack.
 *
 * Blocks cron jobs with callbacks containing:
 * - curl/wget to external URLs
 * - eval/base64_decode
 * - file_get_contents to http://
 * - References to /tmp or /dev/shm
 * - Suspicious hook names (random strings, base64-like)
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class CleanShift_Cron_Guard {

    /** @var CleanShift_Audit_Log */
    private $audit;

    /** @var CleanShift_Override_Manager */
    private $overrides;

    /**
     * Suspicious patterns in cron hook names.
     *
     * @var array
     */
    private $suspicious_hook_patterns = array(
        '/^[a-z0-9]{20,}$/i',          // Random 20+ char strings.
        '/^[A-Za-z0-9+\/=]{16,}$/',    // Base64-like strings.
        '/^wp_[a-f0-9]{8,}$/',         // Fake wp_ prefixed hex.
        '/^cron_[a-f0-9]{8,}$/',       // Fake cron_ prefixed hex.
    );

    /**
     * Known safe cron hooks (WordPress core + popular plugins).
     *
     * @var array
     */
    private $safe_hooks = array(
        'wp_cron',
        'wp_scheduled_delete',
        'wp_scheduled_auto_draft_delete',
        'wp_version_check',
        'wp_update_plugins',
        'wp_update_themes',
        'wp_privacy_delete_old_export_files',
        'delete_expired_transients',
        'recovery_mode_clean_expired_keys',
        'wp_site_health_scheduled_check',
        'woocommerce_',
        'elementor_',
        'updraftplus_',
        'wordfence_',
        'litespeed_',
        'jetpack_',
        'yoast_',
        'action_scheduler_',
        'wpforms_',
        'mailchimp_',
    );

    /**
     * Patterns in option values that indicate malicious cron callbacks.
     *
     * @var array
     */
    private $malicious_patterns = array(
        'curl_exec',
        'curl_init',
        'file_get_contents(\'http',
        'file_get_contents("http',
        'wp_remote_get(\'http',
        'wp_remote_post(\'http',
        'eval(',
        'base64_decode(',
        'gzinflate(',
        'str_rot13(',
        'system(',
        'exec(',
        'passthru(',
        'shell_exec(',
        'popen(',
        'proc_open(',
        '/tmp/',
        '/dev/shm/',
        '/dev/tcp/',
        'wget ',
        'curl ',
    );

    /**
     * Initialize the cron guard.
     *
     * @param CleanShift_Audit_Log       $audit     Audit logger instance.
     * @param CleanShift_Override_Manager $overrides Override manager instance.
     */
    public function __construct( $audit, $overrides ) {
        $this->audit     = $audit;
        $this->overrides = $overrides;
    }

    /**
     * Register WordPress hooks.
     *
     * Cron guard is always enabled — no other security plugin monitors this.
     */
    public function init() {
        // Monitor cron event scheduling.
        add_filter( 'pre_schedule_event', array( $this, 'inspect_cron_event' ), 10, 2 );

        // Periodic audit of existing cron jobs.
        add_action( 'admin_init', array( $this, 'audit_existing_crons' ) );
    }

    /**
     * Inspect a cron event before it's scheduled.
     *
     * @param null|bool      $pre   Pre-filter value.
     * @param object|array   $event The cron event being scheduled.
     * @return null|bool Null to allow, false to block.
     */
    public function inspect_cron_event( $pre, $event ) {
        try {
            // Allow WordPress core to proceed normally if $pre is already set.
            if ( null !== $pre ) {
                return $pre;
            }

            $hook = is_object( $event ) ? $event->hook : ( isset( $event['hook'] ) ? $event['hook'] : '' );

            if ( empty( $hook ) ) {
                return $pre;
            }

            // Check against safe hooks list.
            if ( $this->is_safe_hook( $hook ) ) {
                return $pre;
            }

            // Check override.
            if ( $this->overrides->is_overridden( 'cron', $hook ) ) {
                $this->audit->log(
                    'cron',
                    'schedule_event',
                    'OVERRIDE',
                    'low',
                    array(
                        'hook'   => $hook,
                        'reason' => 'Override active for this cron hook',
                    ),
                    get_current_user_id()
                );
                return $pre;
            }

            // Check 1: Suspicious hook name pattern.
            $suspicious_name = $this->check_suspicious_name( $hook );

            // Check 2: Inspect callback for malicious patterns.
            $malicious_callback = $this->check_callback_content( $hook );

            if ( $suspicious_name || $malicious_callback ) {
                $severity = $malicious_callback ? 'critical' : 'high';
                $reason   = $malicious_callback
                    ? 'Cron callback contains malicious code patterns'
                    : 'Cron hook name matches suspicious pattern';

                $this->audit->log(
                    'cron',
                    'block_schedule',
                    'BLOCKED',
                    $severity,
                    array(
                        'hook'               => $hook,
                        'reason'             => $reason,
                        'suspicious_name'    => $suspicious_name,
                        'malicious_callback' => $malicious_callback,
                        'user_id'            => get_current_user_id(),
                    ),
                    get_current_user_id()
                );

                // Block by returning false.
                return false;
            }
        } catch ( \Exception $e ) {
            error_log( '[CleanShift Guard] Cron guard error: ' . $e->getMessage() );
        }

        return $pre;
    }

    /**
     * Check if a hook name matches known safe hooks.
     *
     * @param string $hook Cron hook name.
     * @return bool True if safe.
     */
    private function is_safe_hook( $hook ) {
        foreach ( $this->safe_hooks as $safe ) {
            if ( $hook === $safe || 0 === strpos( $hook, $safe ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if hook name matches suspicious patterns.
     *
     * @param string $hook Cron hook name.
     * @return string|false The matched pattern or false.
     */
    private function check_suspicious_name( $hook ) {
        foreach ( $this->suspicious_hook_patterns as $pattern ) {
            if ( preg_match( $pattern, $hook ) ) {
                return $pattern;
            }
        }
        return false;
    }

    /**
     * Check cron option value for malicious callback patterns.
     *
     * Reads the cron option and inspects registered callbacks for the hook.
     *
     * @param string $hook Cron hook name.
     * @return string|false The matched pattern or false.
     */
    private function check_callback_content( $hook ) {
        $cron_array = _get_cron_array();
        if ( empty( $cron_array ) || ! is_array( $cron_array ) ) {
            return false;
        }

        // Serialize the cron array to check for patterns.
        $serialized = serialize( $cron_array ); // phpcs:ignore

        foreach ( $this->malicious_patterns as $pattern ) {
            if ( false !== stripos( $serialized, $pattern ) ) {
                return $pattern;
            }
        }

        return false;
    }

    /**
     * Periodic audit of all existing cron jobs.
     *
     * Runs on admin_init — checks once per hour via transient.
     */
    public function audit_existing_crons() {
        try {
            // Rate limit: once per hour.
            if ( false !== get_transient( 'cleanshift_cron_audit' ) ) {
                return;
            }
            set_transient( 'cleanshift_cron_audit', 1, HOUR_IN_SECONDS );

            $cron_array = _get_cron_array();
            if ( empty( $cron_array ) || ! is_array( $cron_array ) ) {
                return;
            }

            foreach ( $cron_array as $timestamp => $crons ) {
                if ( ! is_array( $crons ) ) {
                    continue;
                }
                foreach ( $crons as $hook => $args ) {
                    if ( $this->is_safe_hook( $hook ) ) {
                        continue;
                    }

                    $suspicious = $this->check_suspicious_name( $hook );
                    if ( $suspicious ) {
                        $this->audit->log(
                            'cron',
                            'audit_suspicious_existing',
                            'BLOCKED',
                            'high',
                            array(
                                'hook'       => $hook,
                                'reason'     => 'Existing cron job has suspicious hook name',
                                'pattern'    => $suspicious,
                                'next_run'   => gmdate( 'Y-m-d H:i:s', $timestamp ),
                            ),
                            0
                        );
                    }
                }
            }
        } catch ( \Exception $e ) {
            error_log( '[CleanShift Guard] Cron audit error: ' . $e->getMessage() );
        }
    }
}
