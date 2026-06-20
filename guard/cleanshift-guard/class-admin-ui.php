<?php
/**
 * CleanShift Admin UI
 *
 * Provides the WordPress admin interface for the CleanShift Guard:
 * - Dashboard widget with security overview
 * - Settings page with guard toggles, audit log, and overrides
 * - Admin notices for critical blocks
 * - AJAX handlers for override actions
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class CleanShift_Admin_UI {

    /** @var CleanShift_Audit_Log */
    private $audit;

    /** @var CleanShift_Override_Manager */
    private $overrides;

    /** @var CleanShift_Security_Stack */
    private $stack;

    /**
     * Initialize the admin UI.
     *
     * @param CleanShift_Audit_Log       $audit     Audit logger instance.
     * @param CleanShift_Override_Manager $overrides Override manager instance.
     * @param CleanShift_Security_Stack   $stack     Security stack detector.
     */
    public function __construct( $audit, $overrides, $stack ) {
        $this->audit     = $audit;
        $this->overrides = $overrides;
        $this->stack     = $stack;
    }

    /**
     * Register hooks.
     */
    public function init() {
        add_action( 'admin_menu', array( $this, 'register_menu' ) );
        add_action( 'wp_dashboard_setup', array( $this, 'register_dashboard_widget' ) );
        add_action( 'admin_notices', array( $this, 'show_critical_notices' ) );
        add_action( 'wp_ajax_cleanshift_override', array( $this, 'handle_override_ajax' ) );
        add_action( 'wp_ajax_cleanshift_dismiss', array( $this, 'handle_dismiss_ajax' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
    }

    /**
     * Register the admin menu page.
     */
    public function register_menu() {
        add_options_page(
            __( 'CleanShift Guard', 'cleanshift-guard' ),
            __( 'CleanShift Guard', 'cleanshift-guard' ),
            'manage_options',
            'cleanshift-guard',
            array( $this, 'render_settings_page' )
        );
    }

    /**
     * Register the dashboard widget.
     */
    public function register_dashboard_widget() {
        wp_add_dashboard_widget(
            'cleanshift_guard_overview',
            '🛡️ CleanShift Security Guard',
            array( $this, 'render_dashboard_widget' )
        );
    }

    /**
     * Enqueue admin CSS/JS on CleanShift pages.
     *
     * @param string $hook Current admin page hook.
     */
    public function enqueue_assets( $hook ) {
        if ( 'settings_page_cleanshift-guard' !== $hook && 'index.php' !== $hook ) {
            return;
        }

        wp_add_inline_style( 'wp-admin', $this->get_inline_css() );
    }

    /**
     * Render the dashboard widget.
     */
    public function render_dashboard_widget() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $stats  = $this->audit->get_stats( 1 );  // Last 24 hours.
        $config = $this->stack->get_guard_config();
        $active_overrides = count( $this->overrides->get_active() );

        $enabled_count  = count( array_filter( $config ) );
        $disabled_count = count( $config ) - $enabled_count;

        ?>
        <div class="cleanshift-widget">
            <div class="cleanshift-stats-row">
                <div class="cleanshift-stat">
                    <span class="cleanshift-stat-number"><?php echo esc_html( $stats['blocked'] ?? 0 ); ?></span>
                    <span class="cleanshift-stat-label"><?php esc_html_e( 'Blocked (24h)', 'cleanshift-guard' ); ?></span>
                </div>
                <div class="cleanshift-stat">
                    <span class="cleanshift-stat-number"><?php echo esc_html( $enabled_count ); ?>/<?php echo esc_html( count( $config ) ); ?></span>
                    <span class="cleanshift-stat-label"><?php esc_html_e( 'Guards Active', 'cleanshift-guard' ); ?></span>
                </div>
                <div class="cleanshift-stat">
                    <span class="cleanshift-stat-number"><?php echo esc_html( $active_overrides ); ?></span>
                    <span class="cleanshift-stat-label"><?php esc_html_e( 'Active Overrides', 'cleanshift-guard' ); ?></span>
                </div>
            </div>

            <?php
            // Security stack status.
            $detected = array();
            if ( $this->stack->wordfence ) { $detected[] = 'Wordfence'; }
            if ( $this->stack->sucuri ) { $detected[] = 'Sucuri'; }
            if ( $this->stack->ithemes ) { $detected[] = 'iThemes'; }
            if ( $this->stack->imunify360 ) { $detected[] = 'Imunify360'; }
            if ( $this->stack->csf ) { $detected[] = 'CSF'; }
            if ( $this->stack->fail2ban ) { $detected[] = 'Fail2ban'; }
            if ( $this->stack->cloudflare ) { $detected[] = 'Cloudflare'; }

            if ( ! empty( $detected ) ) {
                echo '<p class="cleanshift-stack-info">🔗 ' . esc_html__( 'Co-operating with: ', 'cleanshift-guard' ) . '<strong>' . esc_html( implode( ', ', $detected ) ) . '</strong></p>';
            } else {
                echo '<p class="cleanshift-stack-info cleanshift-standalone">🛡️ <strong>' . esc_html__( 'Standalone mode', 'cleanshift-guard' ) . '</strong> — ' . esc_html__( 'All guards active (no other security plugins detected)', 'cleanshift-guard' ) . '</p>';
            }
            ?>

            <p><a href="<?php echo esc_url( admin_url( 'options-general.php?page=cleanshift-guard' ) ); ?>" class="button"><?php esc_html_e( 'View Full Dashboard', 'cleanshift-guard' ); ?></a></p>
        </div>
        <?php
    }

    /**
     * Render the full settings page.
     */
    public function render_settings_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have permission to access this page.', 'cleanshift-guard' ) );
        }

        $tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'overview'; // phpcs:ignore

        ?>
        <div class="wrap cleanshift-wrap">
            <h1>🛡️ <?php esc_html_e( 'CleanShift Guard', 'cleanshift-guard' ); ?></h1>

            <nav class="nav-tab-wrapper">
                <a href="?page=cleanshift-guard&tab=overview" class="nav-tab <?php echo 'overview' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Overview', 'cleanshift-guard' ); ?></a>
                <a href="?page=cleanshift-guard&tab=guards" class="nav-tab <?php echo 'guards' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Guards', 'cleanshift-guard' ); ?></a>
                <a href="?page=cleanshift-guard&tab=audit" class="nav-tab <?php echo 'audit' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Audit Log', 'cleanshift-guard' ); ?></a>
                <a href="?page=cleanshift-guard&tab=overrides" class="nav-tab <?php echo 'overrides' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Overrides', 'cleanshift-guard' ); ?></a>
            </nav>

            <div class="cleanshift-tab-content">
                <?php
                switch ( $tab ) {
                    case 'guards':
                        $this->render_guards_tab();
                        break;
                    case 'audit':
                        $this->render_audit_tab();
                        break;
                    case 'overrides':
                        $this->render_overrides_tab();
                        break;
                    default:
                        $this->render_overview_tab();
                        break;
                }
                ?>
            </div>
        </div>
        <?php
    }

    /**
     * Render the overview tab.
     */
    private function render_overview_tab() {
        $stats_24h  = $this->audit->get_stats( 1 );
        $stats_7d   = $this->audit->get_stats( 7 );
        $stats_30d  = $this->audit->get_stats( 30 );

        ?>
        <div class="cleanshift-overview">
            <h2><?php esc_html_e( 'Security Statistics', 'cleanshift-guard' ); ?></h2>
            <table class="widefat striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e( 'Period', 'cleanshift-guard' ); ?></th>
                        <th><?php esc_html_e( 'Blocked', 'cleanshift-guard' ); ?></th>
                        <th><?php esc_html_e( 'Allowed', 'cleanshift-guard' ); ?></th>
                        <th><?php esc_html_e( 'Overridden', 'cleanshift-guard' ); ?></th>
                        <th><?php esc_html_e( 'Total Events', 'cleanshift-guard' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong><?php esc_html_e( 'Last 24 Hours', 'cleanshift-guard' ); ?></strong></td>
                        <td class="cleanshift-blocked"><?php echo esc_html( $stats_24h['blocked'] ?? 0 ); ?></td>
                        <td><?php echo esc_html( $stats_24h['allowed'] ?? 0 ); ?></td>
                        <td class="cleanshift-override"><?php echo esc_html( $stats_24h['override'] ?? 0 ); ?></td>
                        <td><?php echo esc_html( $stats_24h['total'] ?? 0 ); ?></td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e( 'Last 7 Days', 'cleanshift-guard' ); ?></strong></td>
                        <td class="cleanshift-blocked"><?php echo esc_html( $stats_7d['blocked'] ?? 0 ); ?></td>
                        <td><?php echo esc_html( $stats_7d['allowed'] ?? 0 ); ?></td>
                        <td class="cleanshift-override"><?php echo esc_html( $stats_7d['override'] ?? 0 ); ?></td>
                        <td><?php echo esc_html( $stats_7d['total'] ?? 0 ); ?></td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e( 'Last 30 Days', 'cleanshift-guard' ); ?></strong></td>
                        <td class="cleanshift-blocked"><?php echo esc_html( $stats_30d['blocked'] ?? 0 ); ?></td>
                        <td><?php echo esc_html( $stats_30d['allowed'] ?? 0 ); ?></td>
                        <td class="cleanshift-override"><?php echo esc_html( $stats_30d['override'] ?? 0 ); ?></td>
                        <td><?php echo esc_html( $stats_30d['total'] ?? 0 ); ?></td>
                    </tr>
                </tbody>
            </table>

            <h2><?php esc_html_e( 'Recent Activity', 'cleanshift-guard' ); ?></h2>
            <?php $this->render_log_table( 10 ); ?>
        </div>
        <?php
    }

    /**
     * Render the guards configuration tab.
     */
    private function render_guards_tab() {
        $config = $this->stack->get_guard_config();
        $labels = array(
            'upload'  => array( 'Upload Guard', 'Blocks PHP in images, webshell uploads' ),
            'login'   => array( 'Login Guard', 'Brute force protection, lockout' ),
            'user'    => array( 'User Guard', 'Blocks rogue admin creation' ),
            'option'  => array( 'Option Guard', 'Blocks malicious wp_options writes' ),
            'cron'    => array( 'Cron Guard', 'Blocks suspicious cron registration' ),
            'api'     => array( 'API Guard', 'REST API & XML-RPC hardening' ),
            'editor'  => array( 'Editor Guard', 'Monitors file editor usage' ),
            'payload' => array( 'Payload Guard', 'Inspects requests for SQLi, XSS, LFI, RCE' ),
            'request' => array( 'Request Guard', 'Request-level inspection and filtering' ),
            'vpatch'  => array( 'Virtual Patch Guard', 'Blocks known CVE exploit patterns' ),
        );

        ?>
        <h2><?php esc_html_e( 'Guard Status', 'cleanshift-guard' ); ?></h2>
        <table class="widefat striped">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'Guard', 'cleanshift-guard' ); ?></th>
                    <th><?php esc_html_e( 'Description', 'cleanshift-guard' ); ?></th>
                    <th><?php esc_html_e( 'Status', 'cleanshift-guard' ); ?></th>
                    <th><?php esc_html_e( 'Reason', 'cleanshift-guard' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ( $labels as $key => $info ) :
                    $enabled = isset( $config[ $key ] ) ? $config[ $key ] : true;
                    $reason  = $enabled ? __( 'Active — no overlap detected', 'cleanshift-guard' ) : $this->get_disable_reason( $key );
                ?>
                <tr>
                    <td><strong><?php echo esc_html( $info[0] ); ?></strong></td>
                    <td><?php echo esc_html( $info[1] ); ?></td>
                    <td>
                        <?php if ( $enabled ) : ?>
                            <span class="cleanshift-badge cleanshift-badge-active">✅ Active</span>
                        <?php else : ?>
                            <span class="cleanshift-badge cleanshift-badge-deferred">⏸️ Deferred</span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo esc_html( $reason ); ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php
    }

    /**
     * Render the audit log tab.
     */
    private function render_audit_tab() {
        ?>
        <h2><?php esc_html_e( 'Audit Log', 'cleanshift-guard' ); ?></h2>
        <p class="description"><?php esc_html_e( 'All security events are logged here — blocks, overrides, and allowed actions.', 'cleanshift-guard' ); ?></p>
        <?php $this->render_log_table( 50 ); ?>
        <?php
    }

    /**
     * Render the overrides tab.
     */
    private function render_overrides_tab() {
        $overrides = $this->overrides->get_active();

        ?>
        <h2><?php esc_html_e( 'Active Overrides', 'cleanshift-guard' ); ?></h2>
        <?php if ( empty( $overrides ) ) : ?>
            <p><?php esc_html_e( 'No active overrides.', 'cleanshift-guard' ); ?></p>
        <?php else : ?>
            <table class="widefat striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e( 'Guard', 'cleanshift-guard' ); ?></th>
                        <th><?php esc_html_e( 'Pattern', 'cleanshift-guard' ); ?></th>
                        <th><?php esc_html_e( 'Type', 'cleanshift-guard' ); ?></th>
                        <th><?php esc_html_e( 'Reason', 'cleanshift-guard' ); ?></th>
                        <th><?php esc_html_e( 'Created', 'cleanshift-guard' ); ?></th>
                        <th><?php esc_html_e( 'Expires', 'cleanshift-guard' ); ?></th>
                        <th><?php esc_html_e( 'Action', 'cleanshift-guard' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( $overrides as $ov ) : ?>
                    <tr>
                        <td><?php echo esc_html( $ov->guard ); ?></td>
                        <td><code><?php echo esc_html( $ov->pattern ); ?></code></td>
                        <td><?php echo esc_html( $ov->override_type ); ?></td>
                        <td><?php echo esc_html( $ov->reason ); ?></td>
                        <td><?php echo esc_html( $ov->created_at ); ?></td>
                        <td><?php echo esc_html( $ov->expires_at ? $ov->expires_at : '—' ); ?></td>
                        <td>
                            <form method="post" action="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>" style="display:inline;">
                                <?php wp_nonce_field( 'cleanshift_revoke_' . $ov->id ); ?>
                                <input type="hidden" name="action" value="cleanshift_override">
                                <input type="hidden" name="override_action" value="revoke">
                                <input type="hidden" name="override_id" value="<?php echo esc_attr( $ov->id ); ?>">
                                <button type="submit" class="button button-small" onclick="return confirm('Revoke this override?');">
                                    <?php esc_html_e( 'Revoke', 'cleanshift-guard' ); ?>
                                </button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
        <?php
    }

    /**
     * Render the audit log table.
     *
     * @param int $limit Number of entries to show.
     */
    private function render_log_table( $limit = 50 ) {
        $entries = $this->audit->get_recent( $limit );

        if ( empty( $entries ) ) {
            echo '<p>' . esc_html__( 'No events recorded yet.', 'cleanshift-guard' ) . '</p>';
            return;
        }

        ?>
        <table class="widefat striped cleanshift-log-table">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'Time', 'cleanshift-guard' ); ?></th>
                    <th><?php esc_html_e( 'Guard', 'cleanshift-guard' ); ?></th>
                    <th><?php esc_html_e( 'Action', 'cleanshift-guard' ); ?></th>
                    <th><?php esc_html_e( 'Verdict', 'cleanshift-guard' ); ?></th>
                    <th><?php esc_html_e( 'Severity', 'cleanshift-guard' ); ?></th>
                    <th><?php esc_html_e( 'Details', 'cleanshift-guard' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ( $entries as $entry ) :
                    $details_data = json_decode( $entry->details, true );
                    $detail_text  = '';
                    if ( is_array( $details_data ) ) {
                        $detail_text = isset( $details_data['reason'] ) ? $details_data['reason'] : wp_json_encode( $details_data );
                    } else {
                        $detail_text = $entry->details;
                    }
                ?>
                <tr class="cleanshift-verdict-<?php echo esc_attr( strtolower( $entry->verdict ) ); ?>">
                    <td><?php echo esc_html( $entry->timestamp ); ?></td>
                    <td><?php echo esc_html( $entry->guard ); ?></td>
                    <td><?php echo esc_html( $entry->action ); ?></td>
                    <td>
                        <span class="cleanshift-badge cleanshift-badge-<?php echo esc_attr( strtolower( $entry->verdict ) ); ?>">
                            <?php echo esc_html( $entry->verdict ); ?>
                        </span>
                    </td>
                    <td>
                        <span class="cleanshift-severity cleanshift-severity-<?php echo esc_attr( $entry->severity ); ?>">
                            <?php echo esc_html( ucfirst( $entry->severity ) ); ?>
                        </span>
                    </td>
                    <td><small><?php echo esc_html( wp_trim_words( $detail_text, 20 ) ); ?></small></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php
    }

    /**
     * Show admin notices for critical blocks.
     */
    public function show_critical_notices() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        // Check for editor alert.
        $editor_alert = get_transient( 'cleanshift_editor_alert' );
        if ( $editor_alert ) {
            echo '<div class="notice notice-error is-dismissible"><p>';
            echo '<strong>🚨 CleanShift Guard:</strong> ';
            printf(
                /* translators: 1: filename, 2: pattern list */
                esc_html__( 'File "%1$s" was edited and contains suspicious patterns: %2$s', 'cleanshift-guard' ),
                esc_html( $editor_alert['file'] ),
                '<code>' . esc_html( implode( ', ', $editor_alert['patterns'] ) ) . '</code>'
            );
            echo ' <a href="' . esc_url( admin_url( 'options-general.php?page=cleanshift-guard&tab=audit' ) ) . '">' . esc_html__( 'View Audit Log', 'cleanshift-guard' ) . '</a>';
            echo '</p></div>';
        }

        // Show recent critical blocks (last hour).
        $recent_critical = get_transient( 'cleanshift_critical_block' );
        if ( $recent_critical ) {
            echo '<div class="notice notice-error"><p>';
            echo '<strong>🛡️ CleanShift Guard blocked a critical threat:</strong> ';
            echo esc_html( $recent_critical['reason'] );
            echo ' <a href="' . esc_url( admin_url( 'options-general.php?page=cleanshift-guard&tab=audit' ) ) . '">' . esc_html__( 'View Details', 'cleanshift-guard' ) . '</a>';
            echo '</p></div>';
            delete_transient( 'cleanshift_critical_block' );
        }
    }

    /**
     * Handle override AJAX requests.
     */
    public function handle_override_ajax() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Permission denied' );
        }

        // Top-level nonce check before reading any POST data.
        if ( ! isset( $_POST['_wpnonce'] ) ) {
            wp_send_json_error( 'Missing security token' );
        }

        $action_type = isset( $_POST['override_action'] ) ? sanitize_text_field( wp_unslash( $_POST['override_action'] ) ) : '';

        if ( 'revoke' === $action_type ) {
            $id = isset( $_POST['override_id'] ) ? intval( $_POST['override_id'] ) : 0;
            check_admin_referer( 'cleanshift_revoke_' . $id );
            $this->overrides->revoke( $id );
            wp_safe_redirect( admin_url( 'options-general.php?page=cleanshift-guard&tab=overrides' ) );
            exit;
        }

        if ( 'add' === $action_type ) {
            check_admin_referer( 'cleanshift_add_override' );
            $guard   = isset( $_POST['guard'] ) ? sanitize_text_field( wp_unslash( $_POST['guard'] ) ) : '';
            $pattern = isset( $_POST['pattern'] ) ? sanitize_text_field( wp_unslash( $_POST['pattern'] ) ) : '';
            $type    = isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : 'allow_once';
            $reason  = isset( $_POST['reason'] ) ? sanitize_textarea_field( wp_unslash( $_POST['reason'] ) ) : '';

            $allowed_guards = array( 'upload', 'user', 'option', 'login', 'api', 'cron', 'editor' );
            if ( ! in_array( $guard, $allowed_guards, true ) || empty( $pattern ) ) {
                wp_send_json_error( 'Invalid guard name or empty pattern' );
            }

            if ( empty( $reason ) ) {
                wp_send_json_error( 'Reason is required for overrides' );
            }

            $this->overrides->add_override( $guard, $pattern, $type, $reason );
            wp_send_json_success( 'Override added' );
        }

        wp_send_json_error( 'Unknown action' );
    }

    /**
     * Handle dismiss AJAX requests.
     */
    public function handle_dismiss_ajax() {
        check_ajax_referer( 'cleanshift_dismiss' );
        delete_transient( 'cleanshift_editor_alert' );
        wp_send_json_success();
    }

    /**
     * Get the reason a guard was disabled.
     *
     * @param string $guard Guard key.
     * @return string Reason string.
     */
    private function get_disable_reason( $guard ) {
        $reasons = array(
            'upload' => __( 'Deferred to Wordfence file upload scanning', 'cleanshift-guard' ),
            'login'  => __( 'Deferred to Wordfence/Fail2ban login protection', 'cleanshift-guard' ),
            'api'    => __( 'Deferred to Wordfence/iThemes REST API protection', 'cleanshift-guard' ),
            'editor' => __( 'Deferred to Wordfence/iThemes file editor control', 'cleanshift-guard' ),
        );
        return isset( $reasons[ $guard ] ) ? $reasons[ $guard ] : __( 'Covered by another security plugin', 'cleanshift-guard' );
    }

    /**
     * Get inline CSS for the admin pages.
     *
     * @return string CSS styles.
     */
    private function get_inline_css() {
        return '
            .cleanshift-wrap { max-width: 1200px; }
            .cleanshift-tab-content { margin-top: 20px; }
            .cleanshift-stats-row { display: flex; gap: 20px; margin-bottom: 15px; }
            .cleanshift-stat {
                flex: 1; text-align: center; padding: 15px;
                background: #f0f0f1; border-radius: 4px; border-left: 4px solid #2271b1;
            }
            .cleanshift-stat-number { display: block; font-size: 28px; font-weight: 700; color: #1d2327; }
            .cleanshift-stat-label { display: block; font-size: 12px; color: #646970; margin-top: 4px; }
            .cleanshift-badge {
                display: inline-block; padding: 2px 8px; border-radius: 3px;
                font-size: 12px; font-weight: 600;
            }
            .cleanshift-badge-active { background: #d4edda; color: #155724; }
            .cleanshift-badge-deferred { background: #fff3cd; color: #856404; }
            .cleanshift-badge-blocked { background: #f8d7da; color: #721c24; }
            .cleanshift-badge-allowed { background: #d4edda; color: #155724; }
            .cleanshift-badge-override { background: #fff3cd; color: #856404; }
            .cleanshift-severity-critical { color: #dc3545; font-weight: 700; }
            .cleanshift-severity-high { color: #e67700; font-weight: 600; }
            .cleanshift-severity-medium { color: #e6a800; }
            .cleanshift-severity-low { color: #28a745; }
            .cleanshift-blocked { color: #dc3545; font-weight: 600; }
            .cleanshift-override { color: #e67700; font-weight: 600; }
            .cleanshift-stack-info { padding: 8px 12px; background: #f0f6fc; border-radius: 4px; border-left: 4px solid #2271b1; }
            .cleanshift-standalone { border-left-color: #28a745; background: #f0faf0; }
            .cleanshift-log-table td { font-size: 13px; }
            .cleanshift-verdict-blocked { border-left: 3px solid #dc3545; }
            .cleanshift-verdict-override { border-left: 3px solid #e67700; }
        ';
    }
}
