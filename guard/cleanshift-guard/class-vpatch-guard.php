<?php
/**
 * CleanShift Guard — Virtual Patching Guard
 *
 * Blocks requests that match known CVE exploit patterns before they
 * reach vulnerable plugins/themes. This provides Patchstack-level
 * virtual patching without requiring the actual plugin update.
 *
 * Virtual patches are loaded from the intelligence/playbooks/ directory,
 * allowing the agent to push new patches as CVEs are discovered.
 *
 * @package CleanShift Guard
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	return;
}

class CleanShift_VPatch_Guard {

	/**
	 * Virtual patches for known CVEs.
	 *
	 * Each patch defines:
	 * - `cve`:         CVE identifier
	 * - `plugin`:      Affected plugin slug
	 * - `fixed_in`:    Version that fixes the vulnerability
	 * - `paths`:       URL path patterns that the exploit targets
	 * - `methods`:     HTTP methods used by the exploit
	 * - `params`:      Request parameters that carry the payload
	 * - `condition`:   Callable that returns true if the request matches
	 * - `description`: Human-readable description
	 *
	 * @var array[]
	 */
	private static $patches = array(

		// ── CVE-2024-28000: LiteSpeed Cache privilege escalation ────
		'CVE-2024-28000' => array(
			'cve'         => 'CVE-2024-28000',
			'plugin'      => 'litespeed-cache',
			'fixed_in'    => '6.4.1',
			'description' => 'LiteSpeed Cache unauthenticated privilege escalation via role simulation',
			'check'       => 'check_cve_2024_28000',
		),

		// ── CVE-2024-27956: WP-Automatic SQL injection ─────────────
		'CVE-2024-27956' => array(
			'cve'         => 'CVE-2024-27956',
			'plugin'      => 'wp-automatic',
			'fixed_in'    => '3.92.1',
			'description' => 'WP-Automatic SQL injection via CSV import',
			'check'       => 'check_cve_2024_27956',
		),

		// ── CVE-2024-5932: GiveWP PHP object injection ─────────────
		'CVE-2024-5932' => array(
			'cve'         => 'CVE-2024-5932',
			'plugin'      => 'give',
			'fixed_in'    => '3.14.2',
			'description' => 'GiveWP PHP object injection via donation form',
			'check'       => 'check_cve_2024_5932',
		),

		// ── CVE-2024-6386: WPML authenticated RCE ──────────────────
		'CVE-2024-6386' => array(
			'cve'         => 'CVE-2024-6386',
			'plugin'      => 'sitepress-multilingual-cms',
			'fixed_in'    => '4.6.13',
			'description' => 'WPML Twig template server-side template injection',
			'check'       => 'check_cve_2024_6386',
		),

		// ── CVE-2024-10924: Really Simple Security auth bypass ─────
		'CVE-2024-10924' => array(
			'cve'         => 'CVE-2024-10924',
			'plugin'      => 'really-simple-ssl',
			'fixed_in'    => '9.1.2',
			'description' => 'Really Simple Security authentication bypass',
			'check'       => 'check_cve_2024_10924',
		),

		// ── CVE-2024-2194: WP Statistics stored XSS ────────────────
		'CVE-2024-2194' => array(
			'cve'         => 'CVE-2024-2194',
			'plugin'      => 'wp-statistics',
			'fixed_in'    => '14.5.1',
			'description' => 'WP Statistics stored XSS via search parameters',
			'check'       => 'check_cve_2024_2194',
		),

		// ── CVE-2024-1071: Ultimate Member SQL injection ───────────
		'CVE-2024-1071' => array(
			'cve'         => 'CVE-2024-1071',
			'plugin'      => 'ultimate-member',
			'fixed_in'    => '2.8.3',
			'description' => 'Ultimate Member unauthenticated SQL injection',
			'check'       => 'check_cve_2024_1071',
		),

		// ── Generic: PHP file upload via plugin/theme upload ───────
		'GENERIC-PHP-UPLOAD' => array(
			'cve'         => 'GENERIC-PHP-UPLOAD',
			'plugin'      => '*',
			'fixed_in'    => '',
			'description' => 'PHP file upload attempt via plugin/theme routes',
			'check'       => 'check_generic_php_upload',
		),

		// ── Generic: xmlrpc.php brute force ────────────────────────
		'GENERIC-XMLRPC-BRUTE' => array(
			'cve'         => 'GENERIC-XMLRPC-BRUTE',
			'plugin'      => '*',
			'fixed_in'    => '',
			'description' => 'XML-RPC multi-call brute force attempt',
			'check'       => 'check_xmlrpc_brute',
		),

		// ── Generic: wp-config.php exposure ────────────────────────
		'GENERIC-CONFIG-EXPOSURE' => array(
			'cve'         => 'GENERIC-CONFIG-EXPOSURE',
			'plugin'      => '*',
			'fixed_in'    => '',
			'description' => 'wp-config.php backup/exposure attempt',
			'check'       => 'check_config_exposure',
		),
	);

	/**
	 * Run virtual patching checks against the current request.
	 *
	 * Only checks patches for plugins that are actually installed and
	 * running a vulnerable version.
	 *
	 * @return array|null Null if clean, array with CVE details if blocked.
	 */
	public static function inspect() {
		foreach ( self::$patches as $id => $patch ) {
			// For plugin-specific patches, check if the plugin is installed
			// and running a vulnerable version
			if ( $patch['plugin'] !== '*' && ! self::is_plugin_vulnerable( $patch['plugin'], $patch['fixed_in'] ) ) {
				continue;
			}

			$method = $patch['check'];
			if ( method_exists( __CLASS__, $method ) && self::$method() ) {
				return array(
					'cve'         => $patch['cve'],
					'plugin'      => $patch['plugin'],
					'description' => $patch['description'],
					'severity'    => 'critical',
				);
			}
		}

		return null;
	}

	/**
	 * Check if a plugin is installed and running a version below fixed_in.
	 *
	 * @param string $slug     Plugin slug.
	 * @param string $fixed_in Version that contains the fix.
	 *
	 * @return bool True if the plugin is installed AND vulnerable.
	 */
	private static function is_plugin_vulnerable( $slug, $fixed_in ) {
		if ( empty( $fixed_in ) ) {
			return true; // No fix available — always protect
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins = get_plugins();

		foreach ( $plugins as $file => $data ) {
			// Match plugin slug (first directory component of the file path)
			$plugin_slug = dirname( $file );
			if ( $plugin_slug === '.' ) {
				$plugin_slug = basename( $file, '.php' );
			}

			if ( $plugin_slug === $slug ) {
				$installed_version = isset( $data['Version'] ) ? $data['Version'] : '0.0.0';
				return version_compare( $installed_version, $fixed_in, '<' );
			}
		}

		return false; // Plugin not installed
	}

	// ── CVE Check Methods ──────────────────────────────────────────

	/**
	 * CVE-2024-28000: LiteSpeed Cache unauthenticated role simulation.
	 * Detects simulation cookie or litespeed_role parameter.
	 */
	private static function check_cve_2024_28000() {
		// Check for LiteSpeed role simulation cookie
		foreach ( $_COOKIE as $key => $value ) {
			if ( strpos( $key, 'litespeed_role' ) !== false ) {
				return true;
			}
		}
		// Check for role parameter in request
		if ( isset( $_REQUEST['litespeed_role'] ) || isset( $_REQUEST['litespeed_hash'] ) ) {
			return true;
		}
		return false;
	}

	/**
	 * CVE-2024-27956: WP-Automatic SQL injection.
	 * Detects auth parameter bypass and SQL injection in CSV import.
	 */
	private static function check_cve_2024_27956() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		// WP-Automatic SQL injection via the auth bypass
		if ( strpos( $request_uri, 'wp-automatic' ) !== false ) {
			if ( isset( $_REQUEST['auth'] ) || isset( $_POST['q'] ) ) {
				$value = isset( $_POST['q'] ) ? $_POST['q'] : '';
				if ( stripos( $value, 'SELECT' ) !== false || stripos( $value, 'UNION' ) !== false ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * CVE-2024-5932: GiveWP PHP object injection via donation form.
	 */
	private static function check_cve_2024_5932() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		if ( strpos( $request_uri, 'give' ) === false ) {
			return false;
		}

		// Check for serialized PHP objects in donation parameters
		foreach ( $_POST as $key => $value ) {
			if ( is_string( $value ) && preg_match( '/O:\d+:"[^"]+":\d+:{/', $value ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * CVE-2024-6386: WPML SSTI via Twig template injection.
	 */
	private static function check_cve_2024_6386() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		if ( strpos( $request_uri, 'sitepress' ) === false && strpos( $request_uri, 'wpml' ) === false ) {
			return false;
		}

		// Check for Twig template syntax in request parameters
		foreach ( array_merge( $_GET, $_POST ) as $key => $value ) {
			if ( is_string( $value ) && preg_match( '/\{\{.*\}\}|\{%.*%\}/', $value ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * CVE-2024-10924: Really Simple Security auth bypass.
	 */
	private static function check_cve_2024_10924() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		if ( strpos( $request_uri, 'reallysimplessl' ) === false && strpos( $request_uri, 'rsssl' ) === false ) {
			return false;
		}

		// Check for auth bypass via nonce manipulation
		if ( isset( $_REQUEST['rsssl_two_fa_nonce'] ) && isset( $_REQUEST['user_id'] ) ) {
			return true;
		}
		return false;
	}

	/**
	 * CVE-2024-2194: WP Statistics stored XSS via search parameters.
	 */
	private static function check_cve_2024_2194() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		if ( strpos( $request_uri, 'wp-statistics' ) === false ) {
			return false;
		}

		// Check for XSS payloads in search/referrer parameters
		foreach ( $_GET as $key => $value ) {
			if ( is_string( $value ) && preg_match( '/<script|javascript:|on\w+\s*=/i', $value ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * CVE-2024-1071: Ultimate Member SQL injection.
	 */
	private static function check_cve_2024_1071() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		if ( strpos( $request_uri, 'ultimate-member' ) === false && strpos( $request_uri, 'um_' ) === false ) {
			return false;
		}

		// Check for SQL injection in member directory sorting
		if ( isset( $_REQUEST['um_sorting'] ) || isset( $_REQUEST['um_search'] ) ) {
			$value = isset( $_REQUEST['um_sorting'] ) ? $_REQUEST['um_sorting'] : $_REQUEST['um_search'];
			if ( is_string( $value ) && preg_match( '/\b(union|select|insert|update|delete|drop|concat)\b/i', $value ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Generic: PHP file upload attempt.
	 */
	private static function check_generic_php_upload() {
		if ( empty( $_FILES ) ) {
			return false;
		}

		// Skip if user is a logged-in admin
		if ( function_exists( 'current_user_can' ) && current_user_can( 'manage_options' ) ) {
			return false;
		}

		foreach ( $_FILES as $file ) {
			$name = is_array( $file['name'] ) ? implode( ' ', $file['name'] ) : $file['name'];
			if ( preg_match( '/\.ph(p[345s]?|tml|ar)\s*$/i', $name ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Generic: XML-RPC multi-call brute force.
	 */
	private static function check_xmlrpc_brute() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		if ( strpos( $request_uri, 'xmlrpc.php' ) === false ) {
			return false;
		}

		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : '';
		if ( $method !== 'POST' ) {
			return false;
		}

		$body = @file_get_contents( 'php://input' );
		if ( ! $body ) {
			return false;
		}

		// Multi-call with wp.getUsersBlogs = brute force
		if ( stripos( $body, 'system.multicall' ) !== false && stripos( $body, 'wp.getUsersBlogs' ) !== false ) {
			return true;
		}

		return false;
	}

	/**
	 * Generic: wp-config.php exposure attempts.
	 */
	private static function check_config_exposure() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		$patterns = array(
			'wp-config.php.bak',
			'wp-config.php~',
			'wp-config.php.save',
			'wp-config.php.swp',
			'wp-config.php.old',
			'wp-config.bak',
			'wp-config.txt',
			'.wp-config.php',
		);

		foreach ( $patterns as $pattern ) {
			if ( stripos( $request_uri, $pattern ) !== false ) {
				return true;
			}
		}

		return false;
	}
}
