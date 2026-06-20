<?php
/**
 * CleanShift API Guard
 *
 * Hardens REST API and XML-RPC endpoints.
 * - Blocks unauthenticated user enumeration via REST API
 * - Disables XML-RPC (with override option)
 * - Blocks author archive enumeration (?author=N)
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class CleanShift_API_Guard {

    use CleanShift_Client_IP;

    /** @var CleanShift_Audit_Log */
    private $audit;

    /** @var CleanShift_Override_Manager */
    private $overrides;

    /**
     * Initialize the API guard.
     *
     * @param CleanShift_Audit_Log       $audit     Audit logger instance.
     * @param CleanShift_Override_Manager $overrides Override manager instance.
     */
    public function __construct( $audit, $overrides ) {
        $this->audit     = $audit;
        $this->overrides = $overrides;
    }

    /**
     * Register WordPress hooks for API hardening.
     *
     * Skips if Wordfence or iThemes Security handles these endpoints.
     */
    public function init() {
        if ( ! CleanShift_Guard::instance()->guard_enabled( 'api' ) ) {
            return;
        }

        // Block unauthenticated user enumeration via REST API.
        add_filter( 'rest_endpoints', array( $this, 'restrict_user_endpoints' ), 99 );

        // Disable XML-RPC entirely.
        add_filter( 'xmlrpc_enabled', array( $this, 'disable_xmlrpc' ), 99 );

        // Remove XML-RPC discovery headers.
        add_filter( 'wp_headers', array( $this, 'remove_xmlrpc_headers' ), 99 );

        // Block ?author=N enumeration.
        add_action( 'template_redirect', array( $this, 'block_author_enum' ), 1 );

        // Remove oEmbed user discovery.
        remove_action( 'wp_head', 'rest_output_link_wp_head' );
    }

    /**
     * Remove /wp/v2/users endpoint for unauthenticated requests.
     *
     * @param array $endpoints Registered REST endpoints.
     * @return array Filtered endpoints.
     */
    public function restrict_user_endpoints( $endpoints ) {
        try {
            if ( is_user_logged_in() && current_user_can( 'list_users' ) ) {
                return $endpoints;
            }

            // Check override.
            if ( $this->overrides->is_overridden( 'api', 'rest_users' ) ) {
                return $endpoints;
            }

            $blocked_routes = array(
                '/wp/v2/users',
                '/wp/v2/users/(?P<id>[\d]+)',
            );

            foreach ( $blocked_routes as $route ) {
                if ( isset( $endpoints[ $route ] ) ) {
                    unset( $endpoints[ $route ] );
                }
            }

            $this->audit->log(
                'api',
                'block_user_enum_rest',
                'BLOCKED',
                'medium',
                array(
                    'reason'  => 'Unauthenticated REST API user enumeration blocked',
                    'ip'      => $this->get_client_ip(),
                ),
                0,
                0,
                ''
            );
        } catch ( \Exception $e ) {
            error_log( '[CleanShift Guard] API Guard error: ' . $e->getMessage() );
        }

        return $endpoints;
    }

    /**
     * Disable XML-RPC.
     *
     * @param bool $enabled Current XML-RPC status.
     * @return bool Always false unless overridden.
     */
    public function disable_xmlrpc( $enabled ) {
        try {
            if ( $this->overrides->is_overridden( 'api', 'xmlrpc' ) ) {
                return $enabled;
            }

            $this->audit->log(
                'api',
                'block_xmlrpc',
                'BLOCKED',
                'low',
                array(
                    'reason' => 'XML-RPC disabled by CleanShift Guard',
                    'ip'     => $this->get_client_ip(),
                ),
                0,
                0,
                ''
            );

            return false;
        } catch ( \Exception $e ) {
            error_log( '[CleanShift Guard] XML-RPC guard error: ' . $e->getMessage() );
            return $enabled;
        }
    }

    /**
     * Remove X-Pingback and XML-RPC discovery headers.
     *
     * @param array $headers Response headers.
     * @return array Filtered headers.
     */
    public function remove_xmlrpc_headers( $headers ) {
        if ( $this->overrides->is_overridden( 'api', 'xmlrpc' ) ) {
            return $headers;
        }
        unset( $headers['X-Pingback'] );
        return $headers;
    }

    /**
     * Block author archive enumeration via ?author=N.
     *
     * Redirects to homepage when ?author= is used by unauthenticated users.
     */
    public function block_author_enum() {
        try {
            if ( is_admin() ) {
                return;
            }

            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            if ( ! isset( $_GET['author'] ) && ! is_author() ) {
                return;
            }

            if ( is_user_logged_in() && current_user_can( 'list_users' ) ) {
                return;
            }

            if ( $this->overrides->is_overridden( 'api', 'author_enum' ) ) {
                return;
            }

            $this->audit->log(
                'api',
                'block_author_enum',
                'BLOCKED',
                'medium',
                array(
                    'reason'    => 'Author archive enumeration blocked',
                    'ip'        => $this->get_client_ip(),
                    'query'     => isset( $_GET['author'] ) ? intval( $_GET['author'] ) : 'archive', // phpcs:ignore
                ),
                0,
                0,
                ''
            );

            wp_safe_redirect( home_url(), 301 );
            exit;
        } catch ( \Exception $e ) {
            error_log( '[CleanShift Guard] Author enum guard error: ' . $e->getMessage() );
        }
    }

}
