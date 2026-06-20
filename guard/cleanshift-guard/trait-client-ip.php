<?php
/**
 * CleanShift Guard — Client IP Trait
 *
 * Shared IP-detection logic used by Login Guard, API Guard, and Audit Log.
 * Centralised here so proxy-header handling stays DRY.
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Provides a reusable get_client_ip() method.
 *
 * @since 1.0.0
 */
trait CleanShift_Client_IP {

	/**
	 * Determine the client IP address, respecting common proxy headers.
	 *
	 * Only trusts proxy headers when the CLEANSHIFT_TRUSTED_PROXY constant
	 * is defined and truthy — prevents header-spoofing on servers that sit
	 * directly on the internet.
	 *
	 * @return string IPv4 or IPv6 address, or '0.0.0.0' if unknown.
	 */
	private function get_client_ip() {
		// Only trust proxy headers when the site is behind a known reverse proxy.
		if ( defined( 'CLEANSHIFT_TRUSTED_PROXY' ) && CLEANSHIFT_TRUSTED_PROXY ) {
			$proxy_headers = array(
				'HTTP_CF_CONNECTING_IP', // Cloudflare.
				'HTTP_X_FORWARDED_FOR',
				'HTTP_X_REAL_IP',
			);
			foreach ( $proxy_headers as $header ) {
				if ( ! empty( $_SERVER[ $header ] ) ) {
					$ip = explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) ) );
					$ip = trim( $ip[0] );
					if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
						return $ip;
					}
				}
			}
		}

		return isset( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '0.0.0.0';
	}
}
