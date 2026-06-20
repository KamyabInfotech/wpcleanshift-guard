<?php
/**
 * CleanShift Guard — Override Manager
 *
 * Manages the three override levels administrators can apply to
 * blocked actions:
 *
 *   - ALLOW_ONCE   — unblock this specific action instance once.
 *   - ALLOW_PATTERN — add to a permanent allowlist for this pattern.
 *   - KEEP_BLOCKED  — confirm the block, log as acknowledged threat.
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles override CRUD against the cleanshift_overrides table.
 *
 * @since 1.0.0
 */
class CleanShift_Override_Manager {

	/** @var string Override type: unblock once then re-block. */
	const TYPE_ALLOW_ONCE    = 'allow_once';

	/** @var string Override type: permanently allow this pattern. */
	const TYPE_ALLOW_PATTERN = 'allow_pattern';

	/** @var string Override type: confirm block, log acknowledgment. */
	const TYPE_KEEP_BLOCKED  = 'keep_blocked';

	/**
	 * Check whether a given guard + pattern is currently overridden.
	 *
	 * For ALLOW_ONCE overrides this method also deactivates the row after
	 * returning true (single-use token behaviour).
	 *
	 * @param string $guard   Guard identifier.
	 * @param string $pattern Value being checked (filename, username, IP, etc.).
	 * @return bool True if an active override allows this action.
	 */
	public function is_overridden( $guard, $pattern ) {
		try {
			global $wpdb;
			$table = $wpdb->prefix . CLEANSHIFT_GUARD_OVERRIDE_TABLE;

			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$row = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT * FROM `{$table}`
					 WHERE guard = %s
					   AND pattern = %s
					   AND is_active = 1
					   AND ( expires_at IS NULL OR expires_at > NOW() )
					 ORDER BY id DESC
					 LIMIT 1",
					sanitize_key( $guard ),
					$pattern
				)
			);

			if ( ! $row ) {
				return false;
			}

			// KEEP_BLOCKED means the admin confirmed the block — still blocked.
			if ( self::TYPE_KEEP_BLOCKED === $row->override_type ) {
				return false;
			}

			// ALLOW_ONCE — consume the token.
			if ( self::TYPE_ALLOW_ONCE === $row->override_type ) {
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$wpdb->update(
					$table,
					array( 'is_active' => 0 ),
					array( 'id' => $row->id ),
					array( '%d' ),
					array( '%d' )
				);
			}

			return true;

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Override] is_overridden() error: ' . $e->getMessage() );
			}
			return false;
		}
	}

	/**
	 * Create a new override.
	 *
	 * @param string      $guard   Guard identifier.
	 * @param string      $pattern Pattern to override (filename, username, IP …).
	 * @param string      $type    One of TYPE_ALLOW_ONCE, TYPE_ALLOW_PATTERN, TYPE_KEEP_BLOCKED.
	 * @param string      $reason  Admin-supplied justification (required by policy).
	 * @param string|null $expires Optional ISO-8601 datetime when override expires.
	 * @return int|false  Inserted row ID on success, false on failure.
	 */
	public function add_override( $guard, $pattern, $type, $reason, $expires = null ) {
		try {
			global $wpdb;
			$table = $wpdb->prefix . CLEANSHIFT_GUARD_OVERRIDE_TABLE;

			$allowed_types = array( self::TYPE_ALLOW_ONCE, self::TYPE_ALLOW_PATTERN, self::TYPE_KEEP_BLOCKED );
			if ( ! in_array( $type, $allowed_types, true ) ) {
				return false;
			}

			$current_user_id = get_current_user_id();

			$data = array(
				'guard'         => sanitize_key( $guard ),
				'pattern'       => sanitize_text_field( $pattern ),
				'override_type' => sanitize_key( $type ),
				'created_by'    => absint( $current_user_id ),
				'created_at'    => current_time( 'mysql', true ),
				'reason'        => sanitize_textarea_field( $reason ),
				'is_active'     => 1,
			);

			$formats = array( '%s', '%s', '%s', '%d', '%s', '%s', '%d' );

			if ( $expires ) {
				$data['expires_at'] = sanitize_text_field( $expires );
				$formats[]          = '%s';
			}

			$result = $wpdb->insert( $table, $data, $formats );

			if ( false === $result ) {
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					error_log( '[CleanShift Override] Insert failed: ' . $wpdb->last_error );
				}
				return false;
			}

			// Also log to audit trail.
			$guard_instance = CleanShift_Guard::instance();
			if ( $guard_instance->audit_log ) {
				$guard_instance->audit_log->log(
					$guard,
					'override_created',
					strtoupper( $type ),
					'info',
					array(
						'pattern' => $pattern,
						'reason'  => $reason,
						'expires' => $expires,
					),
					$current_user_id
				);
			}

			return (int) $wpdb->insert_id;

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Override] add_override() error: ' . $e->getMessage() );
			}
			return false;
		}
	}

	/**
	 * Revoke (deactivate) an override by its row ID.
	 *
	 * @param int $id Override row ID.
	 * @return bool True on success.
	 */
	public function revoke( $id ) {
		try {
			global $wpdb;
			$table = $wpdb->prefix . CLEANSHIFT_GUARD_OVERRIDE_TABLE;

			$result = $wpdb->update(
				$table,
				array( 'is_active' => 0 ),
				array( 'id' => absint( $id ) ),
				array( '%d' ),
				array( '%d' )
			);

			return false !== $result;

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Override] revoke() error: ' . $e->getMessage() );
			}
			return false;
		}
	}

	/**
	 * Get all active overrides, optionally filtered by guard.
	 *
	 * @param string|null $guard Guard identifier or null for all.
	 * @return array List of row objects.
	 */
	public function get_active( $guard = null ) {
		try {
			global $wpdb;
			$table = $wpdb->prefix . CLEANSHIFT_GUARD_OVERRIDE_TABLE;

			if ( $guard ) {
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				return $wpdb->get_results(
					$wpdb->prepare(
						"SELECT * FROM `{$table}` WHERE guard = %s AND is_active = 1 AND ( expires_at IS NULL OR expires_at > NOW() ) ORDER BY id DESC",
						sanitize_key( $guard )
					)
				);
			}

			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			return $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM `{$table}` WHERE is_active = %d AND ( expires_at IS NULL OR expires_at > NOW() ) ORDER BY id DESC",
					1
				)
			);

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Override] get_active() error: ' . $e->getMessage() );
			}
			return array();
		}
	}

	/**
	 * Deactivate all overrides whose expiry date has passed.
	 *
	 * @return int Number of rows deactivated.
	 */
	public function cleanup_expired() {
		try {
			global $wpdb;
			$table = $wpdb->prefix . CLEANSHIFT_GUARD_OVERRIDE_TABLE;

			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$affected = $wpdb->query(
				$wpdb->prepare(
					"UPDATE `{$table}` SET is_active = 0 WHERE expires_at IS NOT NULL AND expires_at <= NOW() AND is_active = %d",
					1
				)
			);

			return (int) $affected;

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Override] cleanup_expired() error: ' . $e->getMessage() );
			}
			return 0;
		}
	}

	/**
	 * Create the overrides table via dbDelta.
	 *
	 * @return void
	 */
	public function create_table() {
		global $wpdb;
		$table   = $wpdb->prefix . CLEANSHIFT_GUARD_OVERRIDE_TABLE;
		$charset = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			guard varchar(50) NOT NULL DEFAULT '',
			pattern text NOT NULL,
			override_type varchar(20) NOT NULL DEFAULT '',
			created_by bigint(20) unsigned NOT NULL DEFAULT 0,
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at datetime DEFAULT NULL,
			reason text NOT NULL,
			is_active tinyint(1) NOT NULL DEFAULT 1,
			PRIMARY KEY  (id),
			KEY idx_guard_active (guard, is_active),
			KEY idx_expires (expires_at)
		) {$charset};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}
}
