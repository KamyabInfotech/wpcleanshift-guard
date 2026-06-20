<?php
/**
 * CleanShift Guard — API Reporter
 *
 * Reports guard events (BLOCKED, OVERRIDE) to the central CleanShift API
 * so they appear in the dashboard. Uses non-blocking wp_remote_post with
 * batching to avoid performance impact on the WordPress site.
 *
 * @package CleanShift_Guard
 * @since   1.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Batches and sends guard events to the CleanShift API.
 *
 * Events are collected during the request and flushed on shutdown to
 * minimize network overhead.  Only BLOCKED and OVERRIDE verdicts are
 * reported — ALLOWED events are too noisy.
 *
 * @since 1.1.0
 */
class CleanShift_API_Reporter {

	/**
	 * Events queued for reporting.
	 *
	 * @var array
	 */
	private $queue = array();

	/**
	 * Maximum events per API batch.
	 *
	 * @var int
	 */
	private $batch_size = 25;

	/**
	 * Whether the shutdown hook is registered.
	 *
	 * @var bool
	 */
	private $shutdown_registered = false;

	/**
	 * Initialize the reporter and hook into the audit log.
	 */
	public function init() {
		// Listen for audit events.
		add_action( 'cleanshift_audit_logged', array( $this, 'on_audit_event' ), 10, 5 );

		// Flush on shutdown.
		if ( ! $this->shutdown_registered ) {
			add_action( 'shutdown', array( $this, 'flush' ) );
			$this->shutdown_registered = true;
		}
	}

	/**
	 * Queue a guard event for API reporting.
	 *
	 * Only BLOCKED and OVERRIDE verdicts are reported.
	 *
	 * @param int    $log_id   Audit log row ID.
	 * @param string $guard    Guard name (upload, user, login, etc.).
	 * @param string $action   Action attempted.
	 * @param string $verdict  BLOCKED | ALLOWED | OVERRIDE.
	 * @param string $severity critical | high | medium | low | info.
	 */
	public function on_audit_event( $log_id, $guard, $action, $verdict, $severity ) {
		// Only report significant events.
		if ( ! in_array( $verdict, array( 'BLOCKED', 'OVERRIDE' ), true ) ) {
			return;
		}

		$this->queue[] = array(
			'log_id'    => absint( $log_id ),
			'guard'     => sanitize_key( $guard ),
			'action'    => sanitize_text_field( $action ),
			'verdict'   => sanitize_text_field( $verdict ),
			'severity'  => sanitize_key( $severity ),
			'site_url'  => home_url(),
			'site_path' => ABSPATH,
			'timestamp' => gmdate( 'Y-m-d\TH:i:s\Z' ),
		);

		// Auto-flush if batch is full.
		if ( count( $this->queue ) >= $this->batch_size ) {
			$this->flush();
		}
	}

	/**
	 * Send queued events to the CleanShift API.
	 *
	 * Uses non-blocking request (timeout=0.01, blocking=false) to avoid
	 * slowing down the WordPress request.
	 */
	public function flush() {
		if ( empty( $this->queue ) ) {
			return;
		}

		$api_url = $this->get_api_url();
		$api_key = $this->get_api_key();

		if ( empty( $api_url ) || empty( $api_key ) ) {
			// Not configured — clear queue silently.
			$this->queue = array();
			return;
		}

		$events = $this->queue;
		$this->queue = array();

		$endpoint = trailingslashit( $api_url ) . 'guard/events';

		$response = wp_remote_post(
			$endpoint,
			array(
				'timeout'   => 2,
				'blocking'  => false,
				'headers'   => array(
					'Content-Type'  => 'application/json',
					'X-API-Key'     => $api_key,
					'X-Guard-Site'  => home_url(),
				),
				'body'      => wp_json_encode( array(
					'events' => $events,
				) ),
				'sslverify' => apply_filters( 'cleanshift_api_sslverify', true ),
			)
		);

		if ( is_wp_error( $response ) ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Guard] API report failed: ' . $response->get_error_message() );
			}
		}
	}

	/**
	 * Get the CleanShift API URL from the agent config.
	 *
	 * Reads from the agent's config file (set during install) or from
	 * a WordPress option as fallback.
	 *
	 * @return string API URL or empty string.
	 */
	private function get_api_url() {
		// Check WP option first (set via admin UI).
		$url = get_option( 'cleanshift_api_url', '' );
		if ( ! empty( $url ) ) {
			return $url;
		}

		// Fallback: read from agent config.
		$config_paths = array(
			'/root/.cleanshift/config.yml',
			'/root/.cleanshift/config.yaml',
			'/opt/cleanshift/config/config.yaml',
		);

		foreach ( $config_paths as $path ) {
			if ( is_readable( $path ) ) {
				$content = file_get_contents( $path );
				if ( preg_match( '/url:\s*["\']?([^"\'\\s]+)/', $content, $matches ) ) {
					return rtrim( $matches[1], '/' );
				}
			}
		}

		return '';
	}

	/**
	 * Get the API key from the agent config.
	 *
	 * @return string API key or empty string.
	 */
	private function get_api_key() {
		// Check WP option first.
		$key = get_option( 'cleanshift_api_key', '' );
		if ( ! empty( $key ) ) {
			return $key;
		}

		// Fallback: read from agent config.
		$config_paths = array(
			'/root/.cleanshift/config.yml',
			'/root/.cleanshift/config.yaml',
			'/opt/cleanshift/config/config.yaml',
		);

		foreach ( $config_paths as $path ) {
			if ( is_readable( $path ) ) {
				$content = file_get_contents( $path );
				if ( preg_match( '/key:\s*["\']?([^"\'\\s]+)/', $content, $matches ) ) {
					return $matches[1];
				}
			}
		}

		return '';
	}
}
