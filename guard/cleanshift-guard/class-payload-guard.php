<?php
/**
 * CleanShift Guard — Payload Inspection Guard
 *
 * Inspects HTTP request payloads (POST body, query strings, headers) for
 * common attack patterns: SQL injection, XSS, Local File Inclusion (LFI),
 * Remote Code Execution (RCE), and path traversal.
 *
 * This provides Wordfence/Patchstack-level request filtering at the
 * application layer, catching attacks that bypass server-level rules.
 *
 * @package CleanShift Guard
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	return;
}

class CleanShift_Payload_Guard {

	/**
	 * Attack patterns with severity levels.
	 *
	 * Each pattern is a regex that matches a common attack vector.
	 * Patterns are ordered by severity (critical → low).
	 *
	 * @var array<string, array{pattern: string, severity: string, description: string}>
	 */
	private static $patterns = array(

		// ── SQL Injection ──────────────────────────────────────
		'sqli_union' => array(
			'pattern'     => '/\bunion\b[\s\/\*]+\b(all\b[\s\/\*]+)?\bselect\b/i',
			'severity'    => 'critical',
			'description' => 'SQL injection: UNION SELECT',
		),
		'sqli_sleep' => array(
			'pattern'     => '/\b(sleep|benchmark|waitfor\s+delay)\s*\(/i',
			'severity'    => 'critical',
			'description' => 'SQL injection: timing attack',
		),
		'sqli_into_outfile' => array(
			'pattern'     => '/\binto\s+(out|dump)file\b/i',
			'severity'    => 'critical',
			'description' => 'SQL injection: file write',
		),
		'sqli_or_bypass' => array(
			'pattern'     => '/\'\s*(or|and)\s+[\'\d].*[=<>]/i',
			'severity'    => 'high',
			'description' => 'SQL injection: boolean-based bypass',
		),
		'sqli_comment' => array(
			'pattern'     => '/(\-\-\s|#|\/\*.*\*\/)/i',
			'severity'    => 'medium',
			'description' => 'SQL comment injection',
		),

		// ── Cross-Site Scripting (XSS) ─────────────────────────
		'xss_script_tag' => array(
			'pattern'     => '/<script[\s>]/i',
			'severity'    => 'high',
			'description' => 'XSS: script tag injection',
		),
		'xss_event_handler' => array(
			'pattern'     => '/\bon(error|load|click|mouse|focus|blur|submit|change|key)\s*=/i',
			'severity'    => 'high',
			'description' => 'XSS: event handler injection',
		),
		'xss_javascript_proto' => array(
			'pattern'     => '/javascript\s*:/i',
			'severity'    => 'high',
			'description' => 'XSS: javascript: protocol',
		),
		'xss_data_proto' => array(
			'pattern'     => '/data\s*:\s*text\/html/i',
			'severity'    => 'medium',
			'description' => 'XSS: data: protocol with text/html',
		),

		// ── Local / Remote File Inclusion ──────────────────────
		'lfi_path_traversal' => array(
			'pattern'     => '/\.\.[\/\\\\]/i',
			'severity'    => 'high',
			'description' => 'Path traversal: ../',
		),
		'lfi_etc_passwd' => array(
			'pattern'     => '/\/etc\/(passwd|shadow|hosts)/i',
			'severity'    => 'critical',
			'description' => 'LFI: /etc/passwd access attempt',
		),
		'lfi_proc' => array(
			'pattern'     => '/\/proc\/self\/(environ|fd)/i',
			'severity'    => 'critical',
			'description' => 'LFI: /proc/self access',
		),
		'rfi_include' => array(
			'pattern'     => '/(https?|ftp|php|data|expect|input):\/\//i',
			'severity'    => 'high',
			'description' => 'RFI: remote include attempt',
		),

		// ── Remote Code Execution ──────────────────────────────
		'rce_php_wrapper' => array(
			'pattern'     => '/php:\/\/(filter|input|stdin)/i',
			'severity'    => 'critical',
			'description' => 'RCE: PHP stream wrapper abuse',
		),
		'rce_system_exec' => array(
			'pattern'     => '/\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(/i',
			'severity'    => 'critical',
			'description' => 'RCE: PHP command execution function',
		),
		'rce_backtick' => array(
			'pattern'     => '/`[^`]*\b(cat|ls|id|whoami|wget|curl|nc|bash)\b/',
			'severity'    => 'critical',
			'description' => 'RCE: backtick command execution',
		),

		// ── WordPress-Specific ─────────────────────────────────
		'wp_php_upload' => array(
			'pattern'     => '/\.ph(p[345s]?|tml|ar)\s*$/i',
			'severity'    => 'high',
			'description' => 'PHP file upload attempt',
		),
	);

	/**
	 * Paths that are exempt from payload inspection.
	 *
	 * @var string[]
	 */
	private static $exempt_paths = array(
		'/wp-admin/post.php',          // Post editor (contains HTML)
		'/wp-admin/admin-ajax.php',    // AJAX (too many false positives)
		'/wp-admin/theme-editor.php',  // Theme editor
		'/wp-admin/plugin-editor.php', // Plugin editor
	);

	/**
	 * Parameters exempt from inspection (known to contain HTML/SQL).
	 *
	 * @var string[]
	 */
	private static $exempt_params = array(
		'content',        // Post content (wp_editor)
		'post_content',   // Post content
		'comment',        // Comment content
		'description',    // Category/tag description
		'widget-text',    // Text widgets
	);

	/**
	 * Run payload inspection on the current request.
	 *
	 * @return array|null Null if clean, array with attack details if malicious.
	 */
	public static function inspect() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		// Skip exempt paths
		foreach ( self::$exempt_paths as $path ) {
			if ( strpos( $request_uri, $path ) !== false ) {
				return null;
			}
		}

		// Skip non-form requests to reduce false positives
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : 'GET';
		if ( ! in_array( $method, array( 'GET', 'POST', 'PUT', 'PATCH', 'DELETE' ), true ) ) {
			return null;
		}

		$findings = array();

		// Inspect query string
		if ( ! empty( $_GET ) ) {
			foreach ( $_GET as $key => $value ) {
				if ( in_array( $key, self::$exempt_params, true ) ) {
					continue;
				}
				$match = self::check_value( $value, "GET[{$key}]" );
				if ( $match ) {
					$findings[] = $match;
				}
			}
		}

		// Inspect POST data
		if ( ! empty( $_POST ) ) {
			foreach ( $_POST as $key => $value ) {
				if ( in_array( $key, self::$exempt_params, true ) ) {
					continue;
				}
				$match = self::check_value( $value, "POST[{$key}]" );
				if ( $match ) {
					$findings[] = $match;
				}
			}
		}

		// Inspect cookies (limited — mainly auth bypass attacks)
		if ( ! empty( $_COOKIE ) ) {
			foreach ( $_COOKIE as $key => $value ) {
				if ( strpos( $key, 'wordpress_' ) === 0 ) {
					continue; // Skip WP auth cookies
				}
				$match = self::check_value( $value, "COOKIE[{$key}]" );
				if ( $match && $match['severity'] === 'critical' ) {
					$findings[] = $match; // Only flag critical in cookies
				}
			}
		}

		if ( empty( $findings ) ) {
			return null;
		}

		// Return the highest-severity finding
		usort( $findings, function ( $a, $b ) {
			$order = array( 'critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3 );
			return ( $order[ $a['severity'] ] ?? 99 ) - ( $order[ $b['severity'] ] ?? 99 );
		} );

		return $findings[0];
	}

	/**
	 * Check a single value against all attack patterns.
	 *
	 * @param mixed  $value  The value to check.
	 * @param string $source Description of where the value came from.
	 *
	 * @return array|null Null if clean, array with pattern details if match.
	 */
	private static function check_value( $value, $source ) {
		if ( ! is_string( $value ) ) {
			if ( is_array( $value ) ) {
				foreach ( $value as $k => $v ) {
					$result = self::check_value( $v, "{$source}[{$k}]" );
					if ( $result ) {
						return $result;
					}
				}
			}
			return null;
		}

		// Skip very short values (unlikely to contain attacks)
		if ( strlen( $value ) < 4 ) {
			return null;
		}

		// URL-decode the value for inspection
		$decoded = urldecode( $value );

		foreach ( self::$patterns as $name => $rule ) {
			if ( preg_match( $rule['pattern'], $decoded ) ) {
				return array(
					'pattern'     => $name,
					'severity'    => $rule['severity'],
					'description' => $rule['description'],
					'source'      => $source,
					'value_hint'  => substr( $decoded, 0, 80 ),
				);
			}
		}

		return null;
	}
}
