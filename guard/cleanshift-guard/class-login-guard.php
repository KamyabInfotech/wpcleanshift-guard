<?php
/**
 * CleanShift Guard — Login Guard
 *
 * Brute-force protection using WordPress transients for state tracking.
 *
 * Features:
 *   - IP-based rate limiting (5 failures in 10 minutes = lockout).
 *   - Escalating lockout duration (30m → 1h → 2h → 24h).
 *   - 'admin' username probe detection (block if user doesn't exist).
 *   - Localhost / server-IP whitelist.
 *   - Defers to Wordfence, Fail2ban, or Imunify360 when present.
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Brute-force login guard.
 *
 * @since 1.0.0
 */
class CleanShift_Login_Guard {

	use CleanShift_Client_IP;

	/** @var int Maximum failed attempts before lockout. */
	const MAX_ATTEMPTS = 5;

	/** @var int Window (seconds) in which failures are counted. */
	const ATTEMPT_WINDOW = 600; // 10 minutes.

	/** @var int Base lockout duration (seconds). */
	const BASE_LOCKOUT = 1800; // 30 minutes.

	/**
	 * Lockout duration multipliers for repeat offenders.
	 *
	 * @var array<int, int>
	 */
	private $lockout_escalation = array(
		1 => 1800,   // 30 minutes.
		2 => 3600,   // 1 hour.
		3 => 7200,   // 2 hours.
		4 => 86400,  // 24 hours.
	);

	/**
	 * IPs that should never be locked out.
	 *
	 * @var array<int, string>
	 */
	private $whitelisted_ips = array(
		'127.0.0.1',
		'::1',
	);

	/**
	 * Register authentication hooks.
	 *
	 * @return void
	 */
	public function init() {
		if ( ! CleanShift_Guard::instance()->guard_enabled( 'login' ) ) {
			return;
		}

		// Add server IP to whitelist.
		if ( ! empty( $_SERVER['SERVER_ADDR'] ) ) {
			$this->whitelisted_ips[] = sanitize_text_field( $_SERVER['SERVER_ADDR'] );
		}

		add_filter( 'authenticate', array( $this, 'check_lockout' ), 30, 3 );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 1 );
		add_action( 'wp_login', array( $this, 'on_login_success' ), 10, 2 );
	}

	/**
	 * Check whether the connecting IP is currently locked out.
	 *
	 * Hooked to `authenticate` at priority 30 (after core validation).
	 *
	 * @param WP_User|WP_Error|null $user     Authenticated user or error.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password.
	 * @return WP_User|WP_Error
	 */
	public function check_lockout( $user, $username, $password ) {
		try {
			// Skip for WP-CLI.
			if ( defined( 'WP_CLI' ) && WP_CLI ) {
				return $user;
			}

			$ip = $this->get_client_ip();

			if ( $this->is_whitelisted( $ip ) ) {
				return $user;
			}

			// Check if IP is locked out.
			$lockout_key  = 'cleanshift_lockout_' . md5( $ip );
			$lockout_time = get_transient( $lockout_key );

			if ( false !== $lockout_time ) {
				$this->log_block( $ip, $username, 'ip_locked_out' );

				return new \WP_Error(
					'cleanshift_locked_out',
					'<strong>CleanShift Guard:</strong> Too many failed login attempts. Please try again later.'
				);
			}

			// Block 'admin' username if user doesn't exist (bot probe).
			if ( 'admin' === strtolower( $username ) && ! username_exists( 'admin' ) ) {
				$this->log_block( $ip, $username, 'admin_probe' );

				return new \WP_Error(
					'cleanshift_admin_probe',
					'<strong>CleanShift Guard:</strong> Login denied.'
				);
			}

			return $user;

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Login] check_lockout error: ' . $e->getMessage() );
			}
			return $user;
		}
	}

	/**
	 * Record a failed login attempt and trigger lockout if threshold exceeded.
	 *
	 * @param string $username Username that failed.
	 * @return void
	 */
	public function on_login_failed( $username ) {
		try {
			$ip = $this->get_client_ip();

			if ( $this->is_whitelisted( $ip ) ) {
				return;
			}

			$ip_hash      = md5( $ip );
			$attempt_key  = 'cleanshift_attempts_' . $ip_hash;
			$lockout_key  = 'cleanshift_lockout_' . $ip_hash;
			$strikes_key  = 'cleanshift_strikes_' . $ip_hash;

			// Increment attempt counter.
			$attempts = get_transient( $attempt_key );
			if ( false === $attempts ) {
				$attempts = 0;
			}
			$attempts++;
			set_transient( $attempt_key, $attempts, self::ATTEMPT_WINDOW );

			// Log the failure.
			$guard = CleanShift_Guard::instance();
			$guard->audit_log->log(
				'login',
				'login_failed',
				'ALLOWED',
				'medium',
				array(
					'username' => $username,
					'ip'       => $ip,
					'attempts' => $attempts,
				)
			);

			// Trigger lockout?
			if ( $attempts >= self::MAX_ATTEMPTS ) {
				// Determine lockout duration based on strike count.
				$strikes = get_transient( $strikes_key );
				if ( false === $strikes ) {
					$strikes = 0;
				}
				$strikes++;
				set_transient( $strikes_key, $strikes, DAY_IN_SECONDS );

				$duration = $this->get_lockout_duration( $strikes );
				set_transient( $lockout_key, time(), $duration );

				// Clear attempts counter.
				delete_transient( $attempt_key );

				$guard->audit_log->log(
					'login',
					'ip_lockout',
					'BLOCKED',
					'high',
					array(
						'ip'          => $ip,
						'username'    => $username,
						'strikes'     => $strikes,
						'duration_s'  => $duration,
						'duration_h'  => round( $duration / 3600, 1 ),
					)
				);
			}

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Login] on_login_failed error: ' . $e->getMessage() );
			}
		}
	}

	/**
	 * Clear failed-attempt counter on successful login.
	 *
	 * @param string  $username Logged-in username.
	 * @param WP_User $user     User object.
	 * @return void
	 */
	public function on_login_success( $username, $user ) {
		try {
			$ip      = $this->get_client_ip();
			$ip_hash = md5( $ip );

			delete_transient( 'cleanshift_attempts_' . $ip_hash );
			delete_transient( 'cleanshift_lockout_' . $ip_hash );

			$guard = CleanShift_Guard::instance();
			$guard->audit_log->log(
				'login',
				'login_success',
				'ALLOWED',
				'info',
				array(
					'username' => $username,
					'ip'       => $ip,
				),
				$user->ID
			);
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Login] on_login_success error: ' . $e->getMessage() );
			}
		}
	}

	/**
	 * Calculate the lockout duration based on the strike count.
	 *
	 * @param int $strikes Number of lockouts so far.
	 * @return int Duration in seconds.
	 */
	private function get_lockout_duration( $strikes ) {
		if ( isset( $this->lockout_escalation[ $strikes ] ) ) {
			return $this->lockout_escalation[ $strikes ];
		}
		// Cap at 24 hours for 4+ strikes.
		return 86400;
	}

	/**
	 * Check whether an IP is in the whitelist.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private function is_whitelisted( $ip ) {
		return in_array( $ip, $this->whitelisted_ips, true );
	}

	/**
	 * Log a blocked login attempt.
	 *
	 * @param string $ip       Client IP.
	 * @param string $username Submitted username.
	 * @param string $check    Check identifier.
	 * @return void
	 */
	private function log_block( $ip, $username, $check ) {
		$guard = CleanShift_Guard::instance();
		$guard->audit_log->log(
			'login',
			$check,
			'BLOCKED',
			'high',
			array(
				'ip'       => $ip,
				'username' => $username,
			)
		);
	}

}
