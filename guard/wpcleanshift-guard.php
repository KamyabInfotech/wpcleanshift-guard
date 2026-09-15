<?php
/**
 * Plugin Name: CleanShift Guard
 * Description: Real-time security guard with override & audit logging
 * Version: 1.0.0-rc.445
 * Author: CleanShift Security
 * Plugin URI:   https://cleanshift.osg.co.in
 * Author URI:   https://cleanshift.osg.co.in
 * Requires PHP: 7.4
 * Requires at least: 6.0
 * Text Domain: cleanshift-guard
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * This mu-plugin provides real-time protection against common WordPress
 * attack vectors: malicious uploads, rogue admin creation, option injection,
 * brute-force login, REST/XML-RPC abuse, cron hijacking, and file editor
 * misuse. It is SecurityStack-aware — if Wordfence, Sucuri, iThemes, or
 * server-level tools (CSF, Fail2ban, Imunify360) are present, overlapping
 * guards automatically defer to avoid conflicts.
 *
 * @package CleanShift_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( version_compare( PHP_VERSION, '7.4', '<' ) ) {
	error_log( 'CleanShift Guard: requires PHP 7.4+, current version: ' . PHP_VERSION . ' — guard disabled.' );
	return;
}

define( 'CLEANSHIFT_GUARD_VERSION', '1.0.0-rc.445' );
define( 'CLEANSHIFT_GUARD_DIR', __DIR__ . '/cleanshift-guard/' );
define( 'CLEANSHIFT_GUARD_LOG_TABLE', 'cleanshift_audit_log' );
define( 'CLEANSHIFT_GUARD_OVERRIDE_TABLE', 'cleanshift_overrides' );

// ─── Kill switch: touch /var/run/cleanshift/.cleanshift-disable to emergency-disable ───
$cleanshift_kill_switch_path = '/var/run/cleanshift/.cleanshift-disable';
// Only honor kill switch if owned by root (prevent non-root users from disabling)
if ( file_exists( $cleanshift_kill_switch_path ) ) {
	$cleanshift_kill_stat = @stat( $cleanshift_kill_switch_path );
	if ( $cleanshift_kill_stat && $cleanshift_kill_stat['uid'] === 0 ) {
		return; // Kill switch active, skip guards
	}
	// Non-root kill switch file — ignore it (possible attack)
}

// ─── Self-healing: cooldown after 5 consecutive fatal errors ───
// After 5 consecutive errors the guard enters a cooldown window (default 300 s).
// Once the cooldown expires the error counter resets and the guard retries
// automatically — no manual file deletion required.
//
// Mode selection:
//   - Fail-Safe (default): Guard disables itself during cooldown to prevent site crashes.
//     Suitable for shared hosting where uptime is paramount.
//   - Fail-Secure: Guard blocks ALL requests during cooldown. Prevents attackers from
//     intentionally crashing the guard to bypass it.
//     Enable by: touch /var/run/cleanshift/.cleanshift-fail-secure
//
// Cooldown duration: write desired seconds to /var/run/cleanshift/.cleanshift-cooldown-seconds
//   (e.g. echo 600 > /var/run/cleanshift/.cleanshift-cooldown-seconds). Default: 300.
$cleanshift_error_file    = '/var/run/cleanshift/.cleanshift-error-count';
$cleanshift_cooldown_file = '/var/run/cleanshift/.cleanshift-cooldown-start';
$cleanshift_fail_secure   = file_exists( '/var/run/cleanshift/.cleanshift-fail-secure' );

if ( file_exists( $cleanshift_error_file ) ) {
	$error_count = (int) @file_get_contents( $cleanshift_error_file );
	if ( $error_count >= 5 ) {
		// Read configurable cooldown duration (seconds). Default: 300 (5 minutes).
		$cleanshift_cooldown_cfg  = '/var/run/cleanshift/.cleanshift-cooldown-seconds';
		$cleanshift_cooldown_secs = 300;
		if ( file_exists( $cleanshift_cooldown_cfg ) ) {
			$raw = (int) @file_get_contents( $cleanshift_cooldown_cfg );
			if ( $raw > 0 ) {
				$cleanshift_cooldown_secs = $raw;
			}
		}

		// Check if the cooldown window has expired.
		$cleanshift_cooldown_started = file_exists( $cleanshift_cooldown_file )
			? (int) @file_get_contents( $cleanshift_cooldown_file )
			: 0;

		if ( $cleanshift_cooldown_started > 0
			&& ( time() - $cleanshift_cooldown_started ) >= $cleanshift_cooldown_secs
		) {
			// Cooldown expired — reset error counter and let the guard retry.
			@unlink( $cleanshift_error_file );
			@unlink( $cleanshift_cooldown_file );
			error_log( 'CleanShift Guard: Cooldown expired after ' . $cleanshift_cooldown_secs . 's — error counter reset, retrying.' );
			// Fall through to load the guard normally.
		} else {
			// Still in cooldown — apply fail-safe or fail-secure behavior.
			$remaining = $cleanshift_cooldown_started > 0
				? max( 1, $cleanshift_cooldown_secs - ( time() - $cleanshift_cooldown_started ) )
				: $cleanshift_cooldown_secs;

			if ( $cleanshift_fail_secure ) {
				// FAIL-SECURE: Block all requests — guard is broken but site MUST be protected.
				error_log( 'CleanShift Guard [FAIL-SECURE]: Blocking requests during cooldown (' . $remaining . 's remaining). Will auto-retry after cooldown.' );
				if ( ! defined( 'DOING_CRON' ) && ! defined( 'WP_CLI' ) ) {
					http_response_code( 503 );
					header( 'Retry-After: ' . $remaining );
					echo '<!DOCTYPE html><html><head><title>503 Service Unavailable</title></head><body>';
					echo '<h1>Site Temporarily Unavailable</h1>';
					echo '<p>Security system maintenance in progress. Please try again in a few minutes.</p>';
					echo '</body></html>';
					exit;
				}
			} else {
				// FAIL-SAFE (default): Guard disables itself — site stays up but unprotected.
				error_log( 'CleanShift Guard [FAIL-SAFE]: In cooldown (' . $remaining . 's remaining). Guard disabled, will auto-retry after cooldown.' );
				return;
			}
		}
	}
}

// Load guard components.
require_once CLEANSHIFT_GUARD_DIR . 'trait-client-ip.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-audit-log.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-override-manager.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-security-stack.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-upload-guard.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-user-guard.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-option-guard.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-login-guard.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-api-guard.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-cron-guard.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-editor-guard.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-request-guard.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-payload-guard.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-vpatch-guard.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-admin-ui.php';
require_once CLEANSHIFT_GUARD_DIR . 'class-api-reporter.php';

// Initialize on plugins_loaded so all other plugins are available for detection.
add_action( 'plugins_loaded', function () {
	try {
		CleanShift_Guard::instance()->init();
		// Initialize API reporter — sends guard events to central dashboard.
		$reporter = new CleanShift_API_Reporter();
		$reporter->init();
		// Success — reset error counter and any active cooldown.
		$ef  = '/var/run/cleanshift/.cleanshift-error-count';
		$cdf = '/var/run/cleanshift/.cleanshift-cooldown-start';
		if ( file_exists( $ef ) ) {
			@unlink( $ef );
		}
		if ( file_exists( $cdf ) ) {
			@unlink( $cdf );
		}
	} catch ( \Throwable $e ) {
		// NEVER let the guard crash WordPress.
		$ef  = '/var/run/cleanshift/.cleanshift-error-count';
		$cdf = '/var/run/cleanshift/.cleanshift-cooldown-start';
		$count  = file_exists( $ef ) ? (int) @file_get_contents( $ef ) : 0;
		$ef_dir = dirname( $ef );
		if ( ! is_dir( $ef_dir ) ) {
			@mkdir( $ef_dir, 0700, true );
		}
		$new_count = $count + 1;
		@file_put_contents( $ef, $new_count );
		// When reaching the threshold, record cooldown start timestamp.
		if ( 5 === $new_count && ! file_exists( $cdf ) ) {
			@file_put_contents( $cdf, time() );
		}
		error_log( 'CleanShift Guard error (' . $new_count . '/5): ' . $e->getMessage() );
	}
} );

/**
 * Main guard orchestrator (singleton).
 *
 * Detects the installed SecurityStack, decides which guards to enable,
 * creates DB tables on first run, and boots every component.
 *
 * @since 1.0.0
 */
class CleanShift_Guard {

	use CleanShift_Client_IP;

	/**
	 * Singleton instance.
	 *
	 * @var CleanShift_Guard|null
	 */
	private static $instance = null;

	/**
	 * Security stack detector.
	 *
	 * @var CleanShift_Security_Stack
	 */
	public $security_stack;

	/**
	 * Audit logger.
	 *
	 * @var CleanShift_Audit_Log
	 */
	public $audit_log;

	/**
	 * Override manager.
	 *
	 * @var CleanShift_Override_Manager
	 */
	public $override_manager;

	/**
	 * Map of guard_name => enabled (bool).
	 *
	 * @var array<string, bool>
	 */
	private $guard_config = array();

	/**
	 * Whether init() has already run.
	 *
	 * @var bool
	 */
	private $initialized = false;

	/**
	 * Get or create the singleton instance.
	 *
	 * @return CleanShift_Guard
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Private constructor — use instance() instead.
	 */
	private function __construct() {
		// Intentionally empty.
	}

	/**
	 * Boot every guard component.
	 *
	 * Safe to call multiple times — will only run once.
	 *
	 * @return void
	 */
	public function init() {
		if ( $this->initialized ) {
			return;
		}
		$this->initialized = true;

		// Load translations.
		load_plugin_textdomain( 'cleanshift-guard' );

		try {
			// 1. Create core services.
			$this->audit_log        = new CleanShift_Audit_Log();
			$this->override_manager = new CleanShift_Override_Manager();
			$this->security_stack   = new CleanShift_Security_Stack();

			// 2. Detect existing security tools.
			$this->security_stack->detect();

			// 3. Build guard enable/disable map.
			$this->guard_config = $this->security_stack->get_guard_config();

			// Allow site admins to override guard config via filter.
			$this->guard_config = apply_filters( 'cleanshift_guard_config', $this->guard_config );

			// 4. Ensure DB tables exist (lightweight version-check guard).
			$this->maybe_create_tables();

			// 5. Boot individual guards.
			$this->boot_guards();

		} catch ( \Throwable $e ) {
			// Never crash the site.
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Guard] Init error: ' . $e->getMessage() );
			}
		}
	}

	/**
	 * Check whether a specific guard is enabled.
	 *
	 * @param string $guard Guard identifier (upload, user, option, login, api, cron, editor).
	 * @return bool
	 */
	public function guard_enabled( $guard ) {
		return ! empty( $this->guard_config[ $guard ] );
	}

	/**
	 * Check if the guard is in learning mode.
	 *
	 * For the first 48 hours after install, guards log but don't block.
	 * This prevents false positives during initial setup when plugins
	 * are being configured.
	 *
	 * @return bool True if in learning mode.
	 */
	public function is_learning_mode() {
		$installed = get_option( 'cleanshift_installed_at', '' );
		if ( empty( $installed ) ) {
			update_option( 'cleanshift_installed_at', time(), false );
			return true;
		}
		$hours = ( time() - (int) $installed ) / 3600;
		$learning_hours = (int) apply_filters( 'cleanshift_learning_hours', 48 );
		return $hours < $learning_hours;
	}

	/**
	 * Return the full guard configuration map.
	 *
	 * @return array<string, bool>
	 */
	public function get_guard_config() {
		return $this->guard_config;
	}

	/**
	 * Create database tables if they do not yet exist.
	 *
	 * Uses a lightweight wp_option version check so dbDelta only runs once
	 * per plugin version.
	 *
	 * @return void
	 */
	private function maybe_create_tables() {
		$installed_version = get_option( 'cleanshift_guard_db_version', '' );
		if ( CLEANSHIFT_GUARD_VERSION === $installed_version ) {
			return;
		}

		try {
			$this->audit_log->create_table();
			$this->override_manager->create_table();
			update_option( 'cleanshift_guard_db_version', CLEANSHIFT_GUARD_VERSION, false );
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Guard] Table creation error: ' . $e->getMessage() );
			}
		}
	}

	/**
	 * Instantiate and init each guard component.
	 *
	 * @return void
	 */
	private function boot_guards() {
		// ── Early request guards (run before full WP boot) ──────────
		// Payload inspection and virtual patching run on 'init' at priority 1
		// to catch attacks before any plugin code executes.
		if ( $this->guard_enabled( 'payload' ) ) {
			add_action( 'init', array( $this, 'run_payload_inspection' ), 1 );
		}
		if ( $this->guard_enabled( 'vpatch' ) ) {
			add_action( 'init', array( $this, 'run_virtual_patching' ), 1 );
		}

		// ── Standard guards (hook into WP lifecycle) ───────────────
		$guards = array(
			new CleanShift_Upload_Guard(),
			new CleanShift_User_Guard(),
			new CleanShift_Option_Guard(),
			new CleanShift_Login_Guard(),
			new CleanShift_API_Guard( $this->audit_log, $this->override_manager ),
			new CleanShift_Cron_Guard( $this->audit_log, $this->override_manager ),
			new CleanShift_Editor_Guard( $this->audit_log, $this->override_manager ),
			new CleanShift_Request_Guard( $this->audit_log, $this->override_manager ),
			new CleanShift_Admin_UI( $this->audit_log, $this->override_manager, $this->security_stack ),
		);

		foreach ( $guards as $guard ) {
			try {
				$guard->init();
			} catch ( \Throwable $e ) {
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					error_log( '[CleanShift Guard] Guard boot error (' . get_class( $guard ) . '): ' . $e->getMessage() );
				}
			}
		}

		// Expired-override cleanup on a daily cron.
		if ( ! wp_next_scheduled( 'cleanshift_daily_maintenance' ) ) {
			wp_schedule_event( time(), 'daily', 'cleanshift_daily_maintenance' );
		}
		add_action( 'cleanshift_daily_maintenance', array( $this, 'daily_maintenance' ) );
	}

	/**
	 * Daily housekeeping: purge old audit rows and expired overrides.
	 *
	 * @return void
	 */
	public function daily_maintenance() {
		try {
			$retention_days = (int) apply_filters( 'cleanshift_audit_retention_days', 90 );
			$this->audit_log->cleanup( $retention_days );
			$this->override_manager->cleanup_expired();
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Guard] Maintenance error: ' . $e->getMessage() );
			}
		}
	}

	/**
	 * Cleanup method for deactivation / manual uninstall.
	 *
	 * Clears the scheduled cron event. Since this is a mu-plugin and has
	 * no standard activation/deactivation hooks, call this method manually
	 * when removing the plugin, or use the provided uninstall.php.
	 *
	 * @return void
	 */
	public function deactivate() {
		$timestamp = wp_next_scheduled( 'cleanshift_daily_maintenance' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'cleanshift_daily_maintenance' );
		}
	}

	/**
	 * Run payload inspection on the current request.
	 *
	 * Called on 'init' at priority 1 when the 'payload' guard is enabled.
	 * Inspects GET/POST/COOKIE for SQLi, XSS, LFI, RCE patterns.
	 *
	 * @return void
	 */
	public function run_payload_inspection() {
		try {
			$finding = CleanShift_Payload_Guard::inspect();
			if ( null === $finding ) {
				return; // Clean request
			}

			$ip = CleanShift_Guard::instance()->get_client_ip();

			// In learning mode: log but don't block.
			if ( $this->is_learning_mode() ) {
				$this->audit_log->log( 'payload_detected', 'LEARNING', $ip, array(
					'pattern'     => $finding['pattern'],
					'description' => $finding['description'],
					'severity'    => $finding['severity'],
					'source'      => $finding['source'],
				) );
				return;
			}

			// Block the request.
			$this->audit_log->log( 'payload_blocked', 'BLOCKED', $ip, array(
				'pattern'     => $finding['pattern'],
				'description' => $finding['description'],
				'severity'    => $finding['severity'],
				'source'      => $finding['source'],
			) );

			status_header( 403 );
			nocache_headers();
			wp_die(
				'<h1>403 Forbidden</h1><p>Your request was blocked by the security system.</p>',
				'Forbidden',
				array( 'response' => 403 )
			);

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Guard] Payload inspection error: ' . $e->getMessage() );
			}
		}
	}

	/**
	 * Run virtual patching on the current request.
	 *
	 * Called on 'init' at priority 1 when the 'vpatch' guard is enabled.
	 * Blocks requests matching known CVE exploit patterns for installed
	 * vulnerable plugins.
	 *
	 * @return void
	 */
	public function run_virtual_patching() {
		try {
			$finding = CleanShift_VPatch_Guard::inspect();
			if ( null === $finding ) {
				return; // No exploit pattern matched
			}

			$ip = CleanShift_Guard::instance()->get_client_ip();

			// In learning mode: log but don't block.
			if ( $this->is_learning_mode() ) {
				$this->audit_log->log( 'vpatch_detected', 'LEARNING', $ip, array(
					'cve'         => $finding['cve'],
					'plugin'      => $finding['plugin'],
					'description' => $finding['description'],
				) );
				return;
			}

			// Block the exploit attempt.
			$this->audit_log->log( 'vpatch_blocked', 'BLOCKED', $ip, array(
				'cve'         => $finding['cve'],
				'plugin'      => $finding['plugin'],
				'description' => $finding['description'],
			) );

			status_header( 403 );
			nocache_headers();
			wp_die(
				'<h1>403 Forbidden</h1><p>This request matches a known vulnerability exploit pattern (' . esc_html( $finding['cve'] ) . ') and has been blocked.</p>',
				'Forbidden — Virtual Patch Active',
				array( 'response' => 403 )
			);

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Guard] Virtual patching error: ' . $e->getMessage() );
			}
		}
	}

	/**
	 * Get the client IP address.
	 *
	 * Uses the ClientIP trait if available, otherwise falls back to REMOTE_ADDR.
	 *
	 * @return string
	 */
	// get_client_ip() is provided by the CleanShift_Client_IP trait.
	// It only trusts proxy headers (CF, X-Forwarded-For, X-Real-IP) when
	// CLEANSHIFT_TRUSTED_PROXY is defined, preventing IP spoofing attacks.
}
