<?php
/**
 * CleanShift Guard — User Guard
 *
 * Monitors user creation and profile updates to block rogue admin
 * accounts — the single most common persistence mechanism in
 * WordPress compromises.
 *
 * Detection vectors:
 *   - Disposable email domains (20+ domains).
 *   - Fake WordPress.org / WordPress.com emails.
 *   - Suspicious username patterns (wp-backup*, rootadmin*, etc.).
 *   - Privilege escalation (granting administrator without manage_options).
 *
 * Always enabled — no other security plugin covers this.
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Rogue admin creation guard.
 *
 * @since 1.0.0
 */
class CleanShift_User_Guard {

	/**
	 * Disposable / temporary email domains frequently used by attackers.
	 *
	 * @var array<int, string>
	 */
	private $disposable_domains = array(
		'yopmail.com',
		'guerrillamail.com',
		'guerrillamailblock.com',
		'tempmail.com',
		'mailinator.com',
		'10minutemail.com',
		'throwaway.email',
		'sharklasers.com',
		'grr.la',
		'guerrillamail.info',
		'guerrillamail.net',
		'guerrillamail.org',
		'tempail.com',
		'dispostable.com',
		'maildrop.cc',
		'mailnesia.com',
		'guerrillamail.de',
		'trashmail.com',
		'fakeinbox.com',
		'getnada.com',
		'temp-mail.org',
		'mohmal.com',
		'harakirimail.com',
		'trashmail.me',
	);

	/**
	 * Blocked email domains that impersonate WordPress.
	 *
	 * @var array<int, string>
	 */
	private $impersonation_domains = array(
		'wordpress.com',
		'wordpress.org',
		'wp.com',
		'automattic.com',
	);

	/**
	 * Suspicious username prefix patterns (regex fragments).
	 *
	 * @var array<int, string>
	 */
	private $suspicious_username_patterns = array(
		'^wp[-_]?backup',
		'^backupadmin',
		'^system[_-]?admin',
		'^rootadmin',
		'^wp[-_]?system',
		'^wp[-_]?update',
		'^wp[-_]?support',
		'^seo[-_]?admin',
		'^wp[-_]?security',
		'^admin[-_]?\d{3,}',
		'^wpuser[-_]?\d+',
		'^test[-_]?admin',
		'^service[-_]?account',
		'^default[-_]?admin',
	);

	/**
	 * Register hooks for user creation and profile update.
	 *
	 * @return void
	 */
	public function init() {
		if ( ! CleanShift_Guard::instance()->guard_enabled( 'user' ) ) {
			return;
		}

		add_action( 'user_register', array( $this, 'on_user_register' ), 10, 1 );
		add_action( 'profile_update', array( $this, 'on_profile_update' ), 10, 2 );

		// Also hook into set_user_role to catch role changes.
		add_action( 'set_user_role', array( $this, 'on_role_change' ), 10, 3 );
	}

	/**
	 * Inspect a newly registered user.
	 *
	 * @param int $user_id Newly created user ID.
	 * @return void
	 */
	public function on_user_register( $user_id ) {
		try {
			$user = get_userdata( $user_id );
			if ( ! $user ) {
				return;
			}

			$this->inspect_user( $user, 'create_user' );
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift User] register error: ' . $e->getMessage() );
			}
		}
	}

	/**
	 * Inspect a profile update (email or role change).
	 *
	 * @param int     $user_id       Updated user ID.
	 * @param WP_User $old_user_data Previous user data.
	 * @return void
	 */
	public function on_profile_update( $user_id, $old_user_data ) {
		try {
			$user = get_userdata( $user_id );
			if ( ! $user ) {
				return;
			}

			// Only re-inspect if email changed or role changed.
			$old_email = is_object( $old_user_data ) ? $old_user_data->user_email : '';
			if ( $user->user_email !== $old_email || $user->roles !== $old_user_data->roles ) {
				$this->inspect_user( $user, 'update_user' );
			}
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift User] profile_update error: ' . $e->getMessage() );
			}
		}
	}

	/**
	 * Inspect a role change.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $role      New role.
	 * @param array  $old_roles Previous roles.
	 * @return void
	 */
	public function on_role_change( $user_id, $role, $old_roles ) {
		try {
			// Only care about escalation to administrator.
			if ( 'administrator' !== $role ) {
				return;
			}

			// Was already admin? Skip.
			if ( in_array( 'administrator', (array) $old_roles, true ) ) {
				return;
			}

			$user = get_userdata( $user_id );
			if ( ! $user ) {
				return;
			}

			$this->inspect_user( $user, 'role_escalation' );
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift User] role_change error: ' . $e->getMessage() );
			}
		}
	}

	/**
	 * Run all checks against a user record.
	 *
	 * @param WP_User $user   User object.
	 * @param string  $action Contextual action (create_user, update_user, role_escalation).
	 * @return void
	 */
	private function inspect_user( $user, $action ) {
		$guard   = CleanShift_Guard::instance();
		$user_id = $user->ID;
		$email   = strtolower( $user->user_email );
		$login   = strtolower( $user->user_login );
		$roles   = (array) $user->roles;

		$is_admin = in_array( 'administrator', $roles, true );

		// --- Check 1: Disposable email on admin account ---
		if ( $is_admin ) {
			$domain = $this->extract_domain( $email );

			if ( in_array( $domain, $this->disposable_domains, true ) ) {
				$this->handle_block(
					$user,
					$action,
					'disposable_email',
					'critical',
					sprintf( 'Admin account "%s" uses disposable email domain "%s".', $login, $domain )
				);
				return;
			}

			// --- Check 2: WordPress impersonation domain ---
			if ( in_array( $domain, $this->impersonation_domains, true ) ) {
				$this->handle_block(
					$user,
					$action,
					'impersonation_email',
					'critical',
					sprintf( 'Admin account "%s" uses WordPress impersonation email "@%s".', $login, $domain )
				);
				return;
			}
		}

		// --- Check 3: Suspicious username pattern ---
		foreach ( $this->suspicious_username_patterns as $pattern ) {
			if ( preg_match( '/' . $pattern . '/i', $login ) ) {
				$this->handle_block(
					$user,
					$action,
					'suspicious_username',
					'high',
					sprintf( 'Username "%s" matches suspicious pattern (possible rogue admin).', $login )
				);
				return;
			}
		}

		// --- Check 4: Privilege escalation without proper capability ---
		if ( $is_admin && 'create_user' === $action ) {
			$current_user_id = get_current_user_id();
			if ( $current_user_id && ! user_can( $current_user_id, 'manage_options' ) ) {
				$this->handle_block(
					$user,
					$action,
					'unauthorised_admin_creation',
					'critical',
					sprintf(
						'User #%d attempted to create admin account "%s" without manage_options capability.',
						$current_user_id,
						$login
					)
				);
				return;
			}
		}

		// All checks passed.
		$guard->audit_log->log(
			'user',
			$action,
			'ALLOWED',
			'info',
			array(
				'username' => $login,
				'email'    => $email,
				'roles'    => $roles,
			),
			get_current_user_id()
		);
	}

	/**
	 * Handle a blocked user action: check overrides, log, and (where
	 * possible) remove the user or strip their admin role.
	 *
	 * @param WP_User $user     User object.
	 * @param string  $action   Action context.
	 * @param string  $check    Check identifier.
	 * @param string  $severity Severity level.
	 * @param string  $reason   Human-readable reason.
	 * @return void
	 */
	private function handle_block( $user, $action, $check, $severity, $reason ) {
		$guard  = CleanShift_Guard::instance();
		$login  = $user->user_login;

		// Check override.
		$pattern = $login . ':' . $check;
		if ( $guard->override_manager->is_overridden( 'user', $pattern ) ) {
			$guard->audit_log->log(
				'user',
				$action,
				'OVERRIDE',
				$severity,
				array(
					'username' => $login,
					'email'    => $user->user_email,
					'check'    => $check,
					'reason'   => $reason,
				),
				get_current_user_id()
			);
			return;
		}

		// Learning mode: log but don't block or strip role.
		if ( $guard->is_learning_mode() ) {
			$guard->audit_log->log(
				'user',
				$action,
				'LEARNING',
				$severity,
				array(
					'username' => $login,
					'email'    => $user->user_email,
					'check'    => $check,
					'reason'   => $reason,
					'note'     => 'Would have blocked — guard is in learning mode',
				),
				get_current_user_id()
			);
			return;
		}

		// Log the block.
		$guard->audit_log->log(
			'user',
			$action,
			'BLOCKED',
			$severity,
			array(
				'username' => $login,
				'email'    => $user->user_email,
				'check'    => $check,
				'reason'   => $reason,
			),
			get_current_user_id()
		);

		// Remediation: Strip admin role (downgrade to subscriber).
		// We don't delete the user because that could trigger data-loss.
		if ( in_array( 'administrator', (array) $user->roles, true ) ) {
			$user->set_role( 'subscriber' );
		}
	}

	/**
	 * Extract the domain part from an email address.
	 *
	 * @param string $email Email address.
	 * @return string Domain in lowercase, or empty string.
	 */
	private function extract_domain( $email ) {
		$parts = explode( '@', $email );
		if ( count( $parts ) >= 2 ) {
			return strtolower( trim( array_pop( $parts ) ) );
		}
		return '';
	}
}
