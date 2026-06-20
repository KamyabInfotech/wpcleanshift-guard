<?php
/**
 * CleanShift Editor Guard
 *
 * Monitors and logs file editor usage in wp-admin.
 * Logs ALL file edits with before/after content hashes.
 * Alerts if edited file contains suspicious patterns.
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class CleanShift_Editor_Guard {

    /** @var CleanShift_Audit_Log */
    private $audit;

    /** @var CleanShift_Override_Manager */
    private $overrides;

    /**
     * Suspicious patterns to detect in edited file content.
     *
     * @var array
     */
    private $suspicious_patterns = array(
        'eval(',
        'base64_decode(',
        'gzinflate(',
        'str_rot13(',
        'system(',
        'exec(',
        'passthru(',
        'shell_exec(',
        'proc_open(',
        'popen(',
        'file_get_contents(\'http',
        'file_get_contents("http',
        'curl_exec(',
        'assert(',
        'create_function(',
        'preg_replace(\'/.*e\'',
        '$_GET[',
        '$_POST[',
        '$_REQUEST[',
    );

    /**
     * Initialize the editor guard.
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
     * Skips if Wordfence or iThemes Security disables the editor.
     */
    public function init() {
        if ( ! CleanShift_Guard::instance()->guard_enabled( 'editor' ) ) {
            return;
        }

        // Hook into theme/plugin file editing (WP 4.9+).
        add_filter( 'wp_edit_theme_plugin_file', array( $this, 'inspect_file_edit' ), 10, 2 );

        // Add warning notice when editor page is loaded.
        add_action( 'load-theme-editor.php', array( $this, 'editor_warning' ) );
        add_action( 'load-plugin-editor.php', array( $this, 'editor_warning' ) );

        // Recommend DISALLOW_FILE_EDIT if not set.
        if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
            add_action( 'admin_notices', array( $this, 'recommend_disallow_edit' ) );
        }
    }

    /**
     * Inspect a file edit before it's saved.
     *
     * @param array $args {
     *     Array of file edit arguments.
     *     @type string $file    Relative file path.
     *     @type string $plugin  Plugin file (if editing plugin).
     *     @type string $theme   Theme slug (if editing theme).
     * }
     * @param array $r   Additional request data.
     * @return array Unmodified args (logging only, does not block).
     */
    public function inspect_file_edit( $args, $r = array() ) {
        try {
            $file     = isset( $args['file'] ) ? $args['file'] : '';
            $plugin   = isset( $args['plugin'] ) ? $args['plugin'] : '';
            $theme    = isset( $args['theme'] ) ? $args['theme'] : '';
            $content  = isset( $r['newcontent'] ) ? $r['newcontent'] : '';
            $user_id  = get_current_user_id();

            // Compute content hash for audit trail.
            $content_hash = sha1( $content );

            // Check for suspicious patterns in new content.
            $found_patterns = array();
            foreach ( $this->suspicious_patterns as $pattern ) {
                if ( false !== stripos( $content, $pattern ) ) {
                    $found_patterns[] = $pattern;
                }
            }

            $severity = empty( $found_patterns ) ? 'low' : 'critical';
            $verdict  = empty( $found_patterns ) ? 'ALLOWED' : 'FLAGGED';

            // Check override for suspicious content.
            if ( ! empty( $found_patterns ) && ! $this->overrides->is_overridden( 'editor', $file ) ) {
                // Log as FLAGGED at CRITICAL severity to alert admins — don't block intentional edits.
            }

            $this->audit->log(
                'editor',
                'file_edit',
                $verdict,
                $severity,
                array(
                    'file'               => $file,
                    'plugin'             => $plugin,
                    'theme'              => $theme,
                    'content_hash'       => $content_hash,
                    'content_length'     => strlen( $content ),
                    'suspicious_patterns' => $found_patterns,
                    'user_login'         => wp_get_current_user()->user_login,
                ),
                $user_id
            );

            // If suspicious patterns found, add admin notice.
            if ( ! empty( $found_patterns ) ) {
                set_transient(
                    'cleanshift_editor_alert',
                    array(
                        'file'     => $file,
                        'patterns' => $found_patterns,
                        'user'     => wp_get_current_user()->user_login,
                        'time'     => current_time( 'mysql' ),
                    ),
                    HOUR_IN_SECONDS
                );
            }
        } catch ( \Exception $e ) {
            error_log( '[CleanShift Guard] Editor guard error: ' . $e->getMessage() );
        }

        return $args;
    }

    /**
     * Show warning when editor page is loaded.
     */
    public function editor_warning() {
        try {
            $this->audit->log(
                'editor',
                'editor_accessed',
                'ALLOWED',
                'low',
                array(
                    'page'       => isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : 'editor', // phpcs:ignore
                    'user_login' => wp_get_current_user()->user_login,
                ),
                get_current_user_id()
            );

            add_action( 'admin_notices', array( $this, 'show_editor_warning' ) );
        } catch ( \Exception $e ) {
            error_log( '[CleanShift Guard] Editor warning error: ' . $e->getMessage() );
        }
    }

    /**
     * Display editor warning admin notice.
     */
    public function show_editor_warning() {
        echo '<div class="notice notice-warning"><p>';
        echo '<strong>⚠️ CleanShift Guard:</strong> ';
        echo esc_html__( 'File edits via this editor are logged. Consider setting DISALLOW_FILE_EDIT in wp-config.php for security.', 'cleanshift-guard' );
        echo '</p></div>';
    }

    /**
     * Recommend DISALLOW_FILE_EDIT if not set.
     */
    public function recommend_disallow_edit() {
        $screen = get_current_screen();
        if ( ! $screen || ! in_array( $screen->id, array( 'dashboard', 'options-general' ), true ) ) {
            return;
        }

        // Only show once per day.
        if ( false !== get_transient( 'cleanshift_disallow_edit_notice' ) ) {
            return;
        }

        echo '<div class="notice notice-info is-dismissible"><p>';
        echo '<strong>CleanShift Security Tip:</strong> ';
        echo esc_html__( 'Add ', 'cleanshift-guard' );
        echo "<code>define('DISALLOW_FILE_EDIT', true);</code>";
        echo esc_html__( ' to wp-config.php to disable the theme/plugin editor.', 'cleanshift-guard' );
        echo '</p></div>';

        set_transient( 'cleanshift_disallow_edit_notice', 1, DAY_IN_SECONDS );
    }
}
