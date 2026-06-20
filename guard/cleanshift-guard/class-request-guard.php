<?php
/**
 * CleanShift Guard — Request Guard (WAF Layer)
 *
 * Lightweight request-level firewall that inspects $_GET, $_POST,
 * $_COOKIE, $_REQUEST, and $_SERVER['REQUEST_URI'] for common attack
 * patterns BEFORE WordPress fully loads.
 *
 * Covers: SQL Injection, XSS, RFI/LFI, Command Injection, and
 * WordPress-specific probes (wp-config exposure, .git/.env access,
 * registration abuse, XML-RPC multicall floods).
 *
 * SecurityStack-aware — defers if Wordfence, Sucuri, Imunify360, or
 * another WAF is already handling request filtering.
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Real-time HTTP request inspection guard.
 *
 * @since 1.0.0
 */
class CleanShift_Request_Guard {

	use CleanShift_Client_IP;

	/** @var CleanShift_Audit_Log */
	private $audit;

	/** @var CleanShift_Override_Manager */
	private $overrides;

	/**
	 * SQL injection patterns (case-insensitive).
	 *
	 * @var array<int, string>
	 */
	private $sqli_patterns = array(
		'union\s+(all\s+)?select',
		"['\"]\s*or\s+1\s*=\s*1",
		'--\s*$',
		'/\*.*?\*/',
		'\bchar\s*\(',
		'\bconcat\s*\(',
		'\bgroup_concat\s*\(',
		'\binformation_schema\b',
		'\bbenchmark\s*\(',
		'\bsleep\s*\(',
		'\bload_file\s*\(',
		'\binto\s+outfile\b',
		'\binto\s+dumpfile\b',
		'\bwaitfor\s+delay\b',
		'\bhaving\s+1\s*=\s*1',
		'\border\s+by\s+\d+',
	);

	/**
	 * XSS patterns (case-insensitive).
	 *
	 * @var array<int, string>
	 */
	private $xss_patterns = array(
		'<\s*script',
		'<\s*/\s*script',
		'\bjavascript\s*:',
		'\bvbscript\s*:',
		'\bon(error|load|mouseover|mouseout|click|focus|blur|submit|change|keyup|keydown|mouseenter|mouseleave|dblclick|contextmenu|input|invalid|reset|search|select|drag|drop|copy|cut|paste|abort|canplay|ended|loadeddata|playing|progress|seeking|stalled|suspend|waiting|toggle|wheel|pointerdown|pointerup|animationstart|animationend|animationiteration|transitionend|beforeunload|hashchange|message|online|offline|pagehide|pageshow|popstate|resize|scroll|storage|unload|beforeprint|afterprint)\s*=',
		'\beval\s*\(',
		'\bexpression\s*\(',
		'\bdocument\s*\.\s*cookie',
		'\bdocument\s*\.\s*write',
		'\bfromcharcode\b',
		'\balert\s*\(',
		'\bprompt\s*\(',
		'\bconfirm\s*\(',
		'<\s*iframe',
		'<\s*object',
		'<\s*embed',
		'<\s*applet',
		'<\s*meta\s[^>]*http-equiv',
		'<\s*svg[^>]*\bon\w+\s*=',
	);

	/**
	 * RFI/LFI patterns (case-insensitive).
	 *
	 * @var array<int, string>
	 */
	private $rfi_patterns = array(
		'\.\./\.\./\.\.',
		'\bphp://input\b',
		'\bphp://filter\b',
		'\bdata://text/plain\b',
		'\bexpect://',
		'\bfile://',
		'\bzlib://',
		'\bphar://',
		'\bglob://',
		'\bzip://',
	);

	/**
	 * Command injection patterns (case-insensitive).
	 *
	 * @var array<int, string>
	 */
	private $cmdi_patterns = array(
		';\s*(ls|cat|wget|curl|bash|sh|nc|ncat|python|perl|ruby|php|whoami|id|uname|passwd|shadow|chmod|chown|rm|mv|cp|mkdir|ping|nslookup|dig|traceroute|ifconfig|netstat|kill|pkill|nohup|crontab)\b',
		'\|\s*(ls|cat|wget|curl|bash|sh|nc|ncat|python|perl|ruby|php|whoami|id|uname)\b',
		'&&\s*(ls|cat|wget|curl|bash|sh|nc|ncat|python|perl|ruby|php|whoami|id|uname)\b',
		'`[^`]+`',
		'\$\([^)]+\)',
		'\bsystem\s*\(',
		'\bexec\s*\(',
		'\bpassthru\s*\(',
		'\bshell_exec\s*\(',
		'\bpopen\s*\(',
		'\bproc_open\s*\(',
		'\bpcntl_exec\s*\(',
	);

	/**
	 * WordPress-specific blocked URI patterns.
	 *
	 * @var array<int, string>
	 */
	private $wp_blocked_uris = array(
		'/\.git(/|$)',
		'/\.env$',
		'/wp-config\.php\.bak',
		'/wp-config\.php\.old',
		'/wp-config\.php\.save',
		'/wp-config\.php\.swp',
		'/wp-config\.php~',
		'/\.htpasswd',
		'/\.htaccess\.bak',
		'/debug\.log$',
		'/error_log$',
	);

	/**
	 * Compiled regex cache (built once on first scan).
	 *
	 * @var array<string, string>
	 */
	private $compiled_patterns = array();

	/**
	 * Whether patterns have been compiled.
	 *
	 * @var bool
	 */
	private $patterns_compiled = false;

	/**
	 * Constructor — receives shared services.
	 *
	 * @param CleanShift_Audit_Log       $audit     Audit logger instance.
	 * @param CleanShift_Override_Manager $overrides Override manager instance.
	 */
	public function __construct( $audit, $overrides ) {
		$this->audit     = $audit;
		$this->overrides = $overrides;
	}

	/**
	 * Register the guard.
	 *
	 * Hooks very early into init (priority 1) so the inspection runs
	 * before most WordPress functionality loads.
	 *
	 * @return void
	 */
	public function init() {
		if ( ! CleanShift_Guard::instance()->guard_enabled( 'request' ) ) {
			return;
		}

		// Run as early as possible on init.
		add_action( 'init', array( $this, 'inspect_request' ), 1 );
	}

	/**
	 * Main inspection entry point.
	 *
	 * @return void
	 */
	public function inspect_request() {
		try {
			// --- Whitelist: wp-cron.php internal requests ---
			if ( $this->is_wp_cron_request() ) {
				return;
			}

			// --- Whitelist: logged-in admin users ---
			if ( $this->is_admin_user() ) {
				return;
			}

			// --- Whitelist: WordPress REST API nonce-authenticated requests ---
			// (Customizer, block editor, etc. often contain inline JS-like content)
			if ( $this->is_authenticated_rest_request() ) {
				return;
			}

			// Compile regex patterns once.
			$this->compile_patterns();

			// --- WordPress-specific URI checks ---
			$uri = isset( $_SERVER['REQUEST_URI'] ) ? $this->decode_value( $_SERVER['REQUEST_URI'] ) : '';

			if ( ! empty( $uri ) ) {
				// Block direct wp-config.php access via URL.
				if ( preg_match( '#/wp-config\.php#i', $uri ) ) {
					$this->block_request( 'wp_config_access', 'Direct access to wp-config.php', 'critical' );
					return;
				}

				// Block sensitive file access.
				foreach ( $this->wp_blocked_uris as $pattern ) {
					if ( preg_match( '#' . $pattern . '#i', $uri ) ) {
						$this->block_request( 'sensitive_file_access', 'Access to sensitive file: ' . $uri, 'high' );
						return;
					}
				}

				// Block wp-login.php?action=register when registration is disabled.
				if ( false !== stripos( $uri, 'wp-login.php' ) ) {
					$action = isset( $_GET['action'] ) ? strtolower( $_GET['action'] ) : '';
					if ( 'register' === $action && ! get_option( 'users_can_register' ) ) {
						$this->block_request( 'registration_disabled', 'Registration attempt while registration is disabled', 'medium' );
						return;
					}
				}

				// Rate-limit XML-RPC system.multicall.
				if ( false !== stripos( $uri, 'xmlrpc.php' ) ) {
					$raw_post = file_get_contents( 'php://input' );
					if ( false !== $raw_post && false !== stripos( $raw_post, 'system.multicall' ) ) {
						$this->block_request( 'xmlrpc_multicall', 'XML-RPC system.multicall blocked (brute-force vector)', 'high' );
						return;
					}
				}

				// Check URI itself for attack patterns.
				$threat = $this->scan_value( $uri, 'REQUEST_URI' );
				if ( $threat ) {
					$this->block_request( $threat['type'], $threat['reason'], $threat['severity'] );
					return;
				}
			}

			// --- Scan superglobals ---
			$superglobals = array(
				'GET'    => $_GET,
				'POST'   => $_POST,
				'COOKIE' => $_COOKIE,
			);

			foreach ( $superglobals as $source_name => $source_data ) {
				if ( empty( $source_data ) || ! is_array( $source_data ) ) {
					continue;
				}
				$threat = $this->scan_array( $source_data, $source_name );
				if ( $threat ) {
					$this->block_request( $threat['type'], $threat['reason'], $threat['severity'] );
					return;
				}
			}

			// --- Deep payload inspection (SQLi/XSS/LFI/RCE patterns) ---
			if ( class_exists( 'CleanShift_Payload_Guard' ) ) {
				$payload_result = CleanShift_Payload_Guard::inspect();
				if ( $payload_result ) {
					$this->block_request(
						'payload_' . ( $payload_result['type'] ?? 'attack' ),
						$payload_result['description'] ?? 'Malicious payload detected',
						$payload_result['severity'] ?? 'high'
					);
					return;
				}
			}

			// --- CVE virtual patching ---
			if ( class_exists( 'CleanShift_VPatch_Guard' ) ) {
				$vpatch_result = CleanShift_VPatch_Guard::inspect();
				if ( $vpatch_result ) {
					$this->block_request(
						'vpatch_' . ( $vpatch_result['cve'] ?? 'cve' ),
						$vpatch_result['description'] ?? 'Blocked by virtual patch',
						$vpatch_result['severity'] ?? 'critical'
					);
					return;
				}
			}

		} catch ( \Throwable $e ) {
			// Never crash WordPress.
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Request] inspect error: ' . $e->getMessage() );
			}
		}
	}

	// ─── Pattern compilation ────────────────────────────────────────

	/**
	 * Compile all pattern arrays into single regex strings for speed.
	 *
	 * @return void
	 */
	private function compile_patterns() {
		if ( $this->patterns_compiled ) {
			return;
		}

		$this->compiled_patterns['sqli'] = '/' . implode( '|', $this->sqli_patterns ) . '/is';
		$this->compiled_patterns['xss']  = '/' . implode( '|', $this->xss_patterns ) . '/is';
		$this->compiled_patterns['rfi']  = '/' . implode( '|', $this->rfi_patterns ) . '/is';
		$this->compiled_patterns['cmdi'] = '/' . implode( '|', $this->cmdi_patterns ) . '/is';

		// Also check for http:// / https:// in parameter values (RFI).
		$this->compiled_patterns['rfi_url'] = '#https?://(?!(' . preg_quote( $this->get_site_host(), '#' ) . '))#i';

		$this->patterns_compiled = true;
	}

	// ─── Scanning helpers ───────────────────────────────────────────

	/**
	 * Recursively scan an associative array for attack patterns.
	 *
	 * @param array  $data   Input data ($_GET, $_POST, etc.).
	 * @param string $source Source name for logging.
	 * @param int    $depth  Current recursion depth (safety limit).
	 * @return array|null Threat info or null if clean.
	 */
	private function scan_array( $data, $source, $depth = 0 ) {
		// Prevent DoS via deeply nested arrays.
		if ( $depth > 5 ) {
			return null;
		}

		foreach ( $data as $key => $value ) {
			// Scan the key itself (attackers sometimes inject via keys).
			$decoded_key = $this->decode_value( (string) $key );
			$threat = $this->scan_value( $decoded_key, $source . '[key:' . $key . ']' );
			if ( $threat ) {
				return $threat;
			}

			if ( is_array( $value ) ) {
				$threat = $this->scan_array( $value, $source . '[' . $key . ']', $depth + 1 );
				if ( $threat ) {
					return $threat;
				}
			} else {
				$decoded_value = $this->decode_value( (string) $value );
				$threat = $this->scan_value( $decoded_value, $source . '[' . $key . ']' );
				if ( $threat ) {
					return $threat;
				}
			}
		}

		return null;
	}

	/**
	 * Scan a single string value against all compiled patterns.
	 *
	 * @param string $value  Decoded value to check.
	 * @param string $source Context for logging.
	 * @return array|null Threat info array or null if clean.
	 */
	private function scan_value( $value, $source ) {
		// Skip empty or very short values (can't contain meaningful payload).
		if ( strlen( $value ) < 3 ) {
			return null;
		}

		// SQL Injection.
		if ( preg_match( $this->compiled_patterns['sqli'], $value ) ) {
			return array(
				'type'     => 'sqli',
				'severity' => 'critical',
				'reason'   => 'SQL injection pattern detected in ' . $source,
			);
		}

		// XSS.
		if ( preg_match( $this->compiled_patterns['xss'], $value ) ) {
			return array(
				'type'     => 'xss',
				'severity' => 'high',
				'reason'   => 'Cross-site scripting (XSS) pattern detected in ' . $source,
			);
		}

		// RFI / LFI.
		if ( preg_match( $this->compiled_patterns['rfi'], $value ) ) {
			return array(
				'type'     => 'rfi_lfi',
				'severity' => 'critical',
				'reason'   => 'Remote/Local file inclusion pattern detected in ' . $source,
			);
		}

		// RFI via external URL in parameter value.
		// Only check non-URI sources (don't flag the REQUEST_URI itself for having http).
		if ( 'REQUEST_URI' !== $source && preg_match( $this->compiled_patterns['rfi_url'], $value ) ) {
			return array(
				'type'     => 'rfi_url',
				'severity' => 'high',
				'reason'   => 'External URL in parameter value (potential RFI) in ' . $source,
			);
		}

		// Command Injection.
		if ( preg_match( $this->compiled_patterns['cmdi'], $value ) ) {
			return array(
				'type'     => 'cmdi',
				'severity' => 'critical',
				'reason'   => 'Command injection pattern detected in ' . $source,
			);
		}

		return null;
	}

	// ─── Value decoding ─────────────────────────────────────────────

	/**
	 * Decode URL-encoded values (double-decode to catch evasion).
	 *
	 * @param string $value Raw value.
	 * @return string Decoded value.
	 */
	private function decode_value( $value ) {
		// Double-decode to catch %25xx evasion.
		$decoded = urldecode( urldecode( $value ) );
		// Also decode HTML entities used for evasion.
		$decoded = html_entity_decode( $decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		// Remove null bytes.
		$decoded = str_replace( "\0", '', $decoded );
		return $decoded;
	}

	// ─── Whitelisting helpers ───────────────────────────────────────

	/**
	 * Check if this is a wp-cron.php request.
	 *
	 * @return bool
	 */
	private function is_wp_cron_request() {
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return true;
		}
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		return ( false !== strpos( $uri, '/wp-cron.php' ) );
	}

	/**
	 * Check if the current user is a logged-in administrator.
	 *
	 * @return bool
	 */
	private function is_admin_user() {
		if ( ! function_exists( 'is_user_logged_in' ) || ! function_exists( 'current_user_can' ) ) {
			return false;
		}
		return is_user_logged_in() && current_user_can( 'manage_options' );
	}

	/**
	 * Check if this is an authenticated REST API request.
	 *
	 * The Customizer, block editor, and other WP core features send
	 * data that can look like XSS patterns (inline CSS expressions,
	 * script blocks in post content, etc.). We skip scanning for
	 * authenticated REST requests to avoid false positives.
	 *
	 * @return bool
	 */
	private function is_authenticated_rest_request() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		$is_rest = ( false !== strpos( $uri, '/wp-json/' ) || false !== strpos( $uri, '?rest_route=' ) );

		if ( ! $is_rest ) {
			return false;
		}

		// Check for WP REST nonce (X-WP-Nonce header or _wpnonce param).
		$has_nonce = ! empty( $_SERVER['HTTP_X_WP_NONCE'] )
			|| ! empty( $_GET['_wpnonce'] )
			|| ! empty( $_POST['_wpnonce'] );

		if ( ! $has_nonce ) {
			return false;
		}

		// Verify the user is actually logged in.
		if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() ) {
			return true;
		}

		return false;
	}

	/**
	 * Get the current site hostname for the RFI URL whitelist.
	 *
	 * @return string
	 */
	private function get_site_host() {
		if ( function_exists( 'home_url' ) ) {
			$parsed = wp_parse_url( home_url() );
			return isset( $parsed['host'] ) ? preg_quote( $parsed['host'], '#' ) : 'localhost';
		}
		return isset( $_SERVER['HTTP_HOST'] ) ? preg_quote( $_SERVER['HTTP_HOST'], '#' ) : 'localhost';
	}

	// ─── Blocking ───────────────────────────────────────────────────

	/**
	 * Block a malicious request: log and send 403.
	 *
	 * Respects the override manager and learning mode before actually
	 * blocking.
	 *
	 * @param string $action   Machine action identifier.
	 * @param string $reason   Human-readable block reason.
	 * @param string $severity Severity level.
	 * @return void
	 */
	private function block_request( $action, $reason, $severity ) {
		$guard    = CleanShift_Guard::instance();
		$user_id  = function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0;
		$client_ip = $this->get_client_ip();
		$uri      = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		$details = array(
			'reason'     => $reason,
			'ip'         => $client_ip,
			'uri'        => substr( $uri, 0, 500 ),
			'method'     => isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : 'UNKNOWN',
			'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( $_SERVER['HTTP_USER_AGENT'], 0, 300 ) : '',
		);

		// Check override before blocking.
		if ( $this->overrides->is_overridden( 'request', $action ) ) {
			$this->audit->log( 'request', $action, 'OVERRIDE', $severity, $details, $user_id );
			return;
		}

		// Learning mode: log but don't block.
		if ( $guard->is_learning_mode() ) {
			$details['note'] = 'Would have blocked — guard is in learning mode';
			$this->audit->log( 'request', $action, 'LEARNING', $severity, $details, $user_id );
			return;
		}

		// Block.
		$this->audit->log( 'request', $action, 'BLOCKED', $severity, $details, $user_id );

		// Send 403 and die.
		if ( ! headers_sent() ) {
			http_response_code( 403 );
			header( 'Content-Type: text/html; charset=UTF-8' );
			// No-cache to prevent the 403 from being cached.
			header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
		}

		// Generic message — never reveal what pattern was matched.
		echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>';
		echo '<h1>403 Forbidden</h1>';
		echo '<p>Your request has been blocked by the security system.</p>';
		echo '<p>If you believe this is an error, please contact the site administrator.</p>';
		echo '</body></html>';
		exit;
	}
}
