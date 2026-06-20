<?php
/**
 * CleanShift Guard — Audit Log
 *
 * Records every guard verdict (BLOCKED, ALLOWED, OVERRIDE) to a custom
 * database table for full accountability and forensic review.
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages the cleanshift_audit_log database table.
 *
 * All write operations use $wpdb prepared statements.  Every public
 * method is wrapped in try/catch so a logging failure can never crash
 * the site.
 *
 * @since 1.0.0
 */
class CleanShift_Audit_Log {

	use CleanShift_Client_IP;

	/**
	 * Write counter for auto-cleanup trigger.
	 *
	 * @var int
	 */
	private $write_count = 0;

	/**
	 * Log a guard event.
	 *
	 * @param string $guard           Guard that triggered (upload, user, login, etc.).
	 * @param string $action          Action attempted (upload_file, create_user, etc.).
	 * @param string $verdict         BLOCKED | ALLOWED | OVERRIDE.
	 * @param string $severity        critical | high | medium | low | info.
	 * @param array  $details         Arbitrary context (serialised as JSON).
	 * @param int    $user_id         WordPress user ID (0 = unauthenticated).
	 * @param int    $override_by     Admin who approved override (0 = none).
	 * @param string $override_reason Free-text reason for override.
	 * @return int|false Inserted row ID on success, false on failure.
	 */
	public function log(
		$guard,
		$action,
		$verdict,
		$severity,
		$details = array(),
		$user_id = 0,
		$override_by = 0,
		$override_reason = ''
	) {
		try {
			global $wpdb;
			$table = $wpdb->prefix . CLEANSHIFT_GUARD_LOG_TABLE;

			$user_ip = $this->get_client_ip();

			// Per-IP rate limit: skip if same guard+action+IP logged in last 60 seconds.
			$rate_key = 'cs_rl_' . md5( $guard . $action . $user_ip );
			if ( false !== get_transient( $rate_key ) ) {
				return false; // Rate-limited — skip duplicate log.
			}
			set_transient( $rate_key, 1, 60 );

			// Handle $details: validate pre-encoded JSON strings to prevent XSS.
			if ( is_string( $details ) ) {
				$decoded = json_decode( $details, true );
				$details_json = wp_json_encode( null !== $decoded ? $decoded : array( 'raw' => $details ) );
			} else {
				$details_json = wp_json_encode( $details );
			}

			$result = $wpdb->insert(
				$table,
				array(
					'guard'           => sanitize_key( $guard ),
					'action'          => sanitize_text_field( $action ),
					'verdict'         => sanitize_text_field( $verdict ),
					'severity'        => sanitize_key( $severity ),
					'details'         => $details_json,
					'user_id'         => absint( $user_id ),
					'user_ip'         => sanitize_text_field( $user_ip ),
					'override_by'     => absint( $override_by ),
					'override_reason' => sanitize_textarea_field( $override_reason ),
				),
				array( '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%d', '%s' )
			);

			if ( false === $result ) {
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					error_log( '[CleanShift Audit] Insert failed: ' . $wpdb->last_error );
				}
				return false;
			}

			$insert_id = (int) $wpdb->insert_id;

			// Auto-cleanup: every 100th write, purge entries older than 90 days.
			$this->write_count++;
			if ( 0 === $this->write_count % 100 ) {
				$retention_days = (int) apply_filters( 'cleanshift_audit_retention_days', 90 );
				$this->cleanup( $retention_days );
			}

			// Fire action so other components can react (e.g. admin notices).
			do_action( 'cleanshift_audit_logged', $insert_id, $guard, $action, $verdict, $severity );

			return $insert_id;

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Audit] log() error: ' . $e->getMessage() );
			}
			return false;
		}
	}

	/**
	 * Retrieve recent audit log entries.
	 *
	 * @param int $limit  Maximum rows to return.
	 * @param int $offset Pagination offset.
	 * @return array List of row objects.
	 */
	public function get_recent( $limit = 50, $offset = 0 ) {
		try {
			global $wpdb;
			$table = $wpdb->prefix . CLEANSHIFT_GUARD_LOG_TABLE;

			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			return $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM `{$table}` ORDER BY id DESC LIMIT %d OFFSET %d",
					absint( $limit ),
					absint( $offset )
				)
			);
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Audit] get_recent() error: ' . $e->getMessage() );
			}
			return array();
		}
	}

	/**
	 * Retrieve audit log entries filtered by guard name.
	 *
	 * @param string $guard Guard identifier.
	 * @param int    $limit Maximum rows.
	 * @return array List of row objects.
	 */
	public function get_by_guard( $guard, $limit = 50 ) {
		try {
			global $wpdb;
			$table = $wpdb->prefix . CLEANSHIFT_GUARD_LOG_TABLE;

			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			return $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM `{$table}` WHERE guard = %s ORDER BY id DESC LIMIT %d",
					sanitize_key( $guard ),
					absint( $limit )
				)
			);
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Audit] get_by_guard() error: ' . $e->getMessage() );
			}
			return array();
		}
	}

	/**
	 * Get aggregate statistics for the last N days.
	 *
	 * @param int $days Look-back window.
	 * @return array{blocked: int, allowed: int, override: int, by_guard: array, by_day: array}
	 */
	public function get_stats( $days = 30 ) {
		try {
			global $wpdb;
			$table = $wpdb->prefix . CLEANSHIFT_GUARD_LOG_TABLE;
			$since = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

			// Verdict counts.
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$verdict_rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT verdict, COUNT(*) AS cnt FROM `{$table}` WHERE timestamp >= %s GROUP BY verdict",
					$since
				)
			);

			$stats = array(
				'blocked'  => 0,
				'allowed'  => 0,
				'override' => 0,
				'by_guard' => array(),
				'by_day'   => array(),
			);

			foreach ( $verdict_rows as $row ) {
				$key = strtolower( $row->verdict );
				if ( isset( $stats[ $key ] ) ) {
					$stats[ $key ] = (int) $row->cnt;
				}
			}

			$stats['total'] = $stats['blocked'] + $stats['allowed'] + $stats['override'];

			// Counts per guard.
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$guard_rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT guard, COUNT(*) AS cnt FROM `{$table}` WHERE timestamp >= %s AND verdict = 'BLOCKED' GROUP BY guard ORDER BY cnt DESC",
					$since
				)
			);
			foreach ( $guard_rows as $row ) {
				$stats['by_guard'][ $row->guard ] = (int) $row->cnt;
			}

			// Counts per day.
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$day_rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT DATE(timestamp) AS day, COUNT(*) AS cnt FROM `{$table}` WHERE timestamp >= %s AND verdict = 'BLOCKED' GROUP BY DATE(timestamp) ORDER BY day ASC",
					$since
				)
			);
			foreach ( $day_rows as $row ) {
				$stats['by_day'][ $row->day ] = (int) $row->cnt;
			}

			return $stats;

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Audit] get_stats() error: ' . $e->getMessage() );
			}
			return array( 'blocked' => 0, 'allowed' => 0, 'override' => 0, 'total' => 0, 'by_guard' => array(), 'by_day' => array() );
		}
	}

	/**
	 * Purge audit entries older than a given number of days.
	 *
	 * @param int $days Retention window.
	 * @return int Number of rows deleted.
	 */
	public function cleanup( $days = 90 ) {
		try {
			global $wpdb;
			$table    = $wpdb->prefix . CLEANSHIFT_GUARD_LOG_TABLE;
			$cutoff   = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$deleted = $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM `{$table}` WHERE timestamp < %s",
					$cutoff
				)
			);

			return (int) $deleted;

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Audit] cleanup() error: ' . $e->getMessage() );
			}
			return 0;
		}
	}

	/**
	 * Create the audit log table using dbDelta.
	 *
	 * @return void
	 */
	public function create_table() {
		global $wpdb;
		$table   = $wpdb->prefix . CLEANSHIFT_GUARD_LOG_TABLE;
		$charset = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			timestamp datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			guard varchar(50) NOT NULL DEFAULT '',
			action varchar(50) NOT NULL DEFAULT '',
			verdict varchar(20) NOT NULL DEFAULT '',
			severity varchar(20) NOT NULL DEFAULT '',
			details longtext NOT NULL,
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			user_ip varchar(45) NOT NULL DEFAULT '',
			override_by bigint(20) unsigned NOT NULL DEFAULT 0,
			override_reason text NOT NULL,
			PRIMARY KEY  (id),
			KEY idx_guard (guard),
			KEY idx_verdict (verdict),
			KEY idx_timestamp (timestamp)
		) {$charset};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

}
