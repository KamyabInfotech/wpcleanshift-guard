<?php
/**
 * CleanShift Guard — Option Guard
 *
 * Monitors wp_options writes for injection of malicious content:
 *   - base64_decode + eval chains
 *   - External script injection
 *   - String.fromCharCode obfuscation
 *   - document.write with encoded payloads
 *   - Oversized base64 blobs in non-standard options
 *
 * Whitelists known-safe options (_transient_*, cron, active_plugins, etc.)
 * to avoid false positives.
 *
 * Always enabled — no other security plugin monitors option values.
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Real-time wp_options injection guard.
 *
 * @since 1.0.0
 */
class CleanShift_Option_Guard {

	/**
	 * Option name prefixes that are known-safe and should be skipped.
	 *
	 * @var array<int, string>
	 */
	private $safe_prefixes = array(
		// Only whitelist known WordPress core transient patterns.
		// Do NOT blanket-whitelist all _transient_* — malware can store
		// IoC signatures in arbitrary transients to bypass scanning.
		'_transient_timeout_',
		'_transient_doing_cron',
		'_transient_update_core',
		'_transient_update_plugins',
		'_transient_update_themes',
		'_site_transient_timeout_',
		'_site_transient_update_core',
		'_site_transient_update_plugins',
		'_site_transient_update_themes',
		'_site_transient_browser_',
		'theme_mods_',
		'widget_',
	);

	/**
	 * Exact option names that should never be blocked.
	 *
	 * @var array<int, string>
	 */
	private $safe_options = array(
		'cron',
		'active_plugins',
		'uninstall_plugins',
		'recently_activated',
		'auto_updater.lock',
		'rewrite_rules',
		'db_version',
		'initial_db_version',
		'wp_user_roles',
		'cleanshift_guard_db_version', // Our own option.
	);

	/**
	 * Register the pre_update_option filter.
	 *
	 * @return void
	 */
	public function init() {
		if ( ! CleanShift_Guard::instance()->guard_enabled( 'option' ) ) {
			return;
		}

		add_filter( 'pre_update_option', array( $this, 'inspect_option' ), 1, 3 );
	}

	/**
	 * Inspect an option value before it is saved.
	 *
	 * Hooked to pre_update_option at priority 1 (runs early).
	 *
	 * @param mixed  $value     New option value.
	 * @param string $option    Option name.
	 * @param mixed  $old_value Previous option value.
	 * @return mixed Original $value if allowed, $old_value if blocked.
	 */
	public function inspect_option( $value, $option, $old_value ) {
		try {
			// Skip known-safe options.
			if ( $this->is_safe_option( $option ) ) {
				return $value;
			}

			// Flatten value to string for pattern matching.
			$flat = $this->flatten_value( $value );
			if ( '' === $flat ) {
				return $value;
			}

			// Run pattern checks.
			$block_reason = $this->scan_patterns( $flat, $option );
			if ( $block_reason ) {
				return $this->block_option( $option, $value, $old_value, $block_reason );
			}

			return $value;

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Option] inspect error: ' . $e->getMessage() );
			}
			return $value;
		}
	}

	/**
	 * Check whether an option name is in the safe list.
	 *
	 * @param string $option Option name.
	 * @return bool
	 */
	private function is_safe_option( $option ) {
		if ( in_array( $option, $this->safe_options, true ) ) {
			return true;
		}

		foreach ( $this->safe_prefixes as $prefix ) {
			if ( 0 === strpos( $option, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Convert an option value (scalar, array, or object) to a flat string.
	 *
	 * @param mixed $value Value to flatten.
	 * @return string
	 */
	private function flatten_value( $value ) {
		if ( is_string( $value ) ) {
			return $value;
		}
		if ( is_array( $value ) || is_object( $value ) ) {
			$encoded = wp_json_encode( $value );
			return is_string( $encoded ) ? $encoded : '';
		}
		if ( is_numeric( $value ) ) {
			return (string) $value;
		}
		return '';
	}

	/**
	 * Scan a flattened value against malicious patterns.
	 *
	 * @param string $flat   Flattened option value.
	 * @param string $option Option name (for context).
	 * @return string Block reason, or empty string if clean.
	 */
	private function scan_patterns( $flat, $option ) {

		// 1. base64_decode + eval chain.
		if ( preg_match( '/base64_decode\s*\(/i', $flat ) && preg_match( '/eval\s*\(/i', $flat ) ) {
			return 'Option value contains base64_decode() + eval() chain — a classic code injection pattern.';
		}

		// 2. eval alone with concatenated/obfuscated argument.
		if ( preg_match( '/eval\s*\(\s*(?:gzinflate|str_rot13|gzuncompress|base64_decode)\s*\(/i', $flat ) ) {
			return 'Option value contains eval() with obfuscation function — likely injected malware.';
		}

		// 3. <script> tag loading external JavaScript.
		if ( preg_match( '/<script[^>]+src\s*=\s*["\']https?:\/\//i', $flat ) ) {
			return 'Option value contains a <script> tag loading external JavaScript.';
		}

		// 4. String.fromCharCode obfuscation.
		if ( preg_match( '/String\s*\.\s*fromCharCode\s*\(/i', $flat ) ) {
			return 'Option value contains String.fromCharCode() — commonly used to obfuscate malicious JavaScript.';
		}

		// 5. document.write with encoded content.
		if ( preg_match( '/document\s*\.\s*write\s*\(\s*(?:unescape|decodeURI|atob)\s*\(/i', $flat ) ) {
			return 'Option value contains document.write() with encoded content — a common injection vector.';
		}

		// 6. Oversized base64 blob (>5000 chars) in non-standard options.
		// Match any base64 string longer than 5000 characters.
		if ( preg_match( '/[A-Za-z0-9+\/=]{5000,}/', $flat ) ) {
			return sprintf(
				'Option "%s" contains a base64-encoded blob exceeding 5000 characters — unusual for this option.',
				$option
			);
		}

		// 7. PHP object injection via serialised data.
		if ( preg_match( '/O:\d+:"[^"]+":/', $flat ) && preg_match( '/(?:eval|assert|system|passthru|exec)\s*\(/i', $flat ) ) {
			return 'Option value contains serialised PHP objects with dangerous function references.';
		}

		return '';
	}

	/**
	 * Block an option write: check overrides, log, and return old value.
	 *
	 * @param string $option    Option name.
	 * @param mixed  $value     New (blocked) value.
	 * @param mixed  $old_value Previous (preserved) value.
	 * @param string $reason    Block reason.
	 * @return mixed $old_value to prevent the write.
	 */
	private function block_option( $option, $value, $old_value, $reason ) {
		$guard   = CleanShift_Guard::instance();
		$user_id = get_current_user_id();

		// Check override.
		if ( $guard->override_manager->is_overridden( 'option', $option ) ) {
			$guard->audit_log->log(
				'option',
				'update_option',
				'OVERRIDE',
				'high',
				array(
					'option' => $option,
					'reason' => $reason,
				),
				$user_id
			);
			return $value; // Let the write through.
		}

		$guard->audit_log->log(
			'option',
			'update_option',
			'BLOCKED',
			'high',
			array(
				'option' => $option,
				'reason' => $reason,
			),
			$user_id
		);

		// Return old value to silently prevent the update.
		return $old_value;
	}
}
