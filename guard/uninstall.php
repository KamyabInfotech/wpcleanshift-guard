<?php
/**
 * CleanShift Guard — Uninstall Script
 *
 * Fired when the plugin is uninstalled (deleted) from WordPress.
 * Removes all database tables, options, transients, and scheduled events
 * created by the plugin.
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

// Abort if not called by WordPress uninstall mechanism.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// 1. Drop custom database tables.
$tables = array(
	$wpdb->prefix . 'cleanshift_audit_log',
	$wpdb->prefix . 'cleanshift_overrides',
);

foreach ( $tables as $table ) {
	// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange
	$wpdb->query( "DROP TABLE IF EXISTS `{$table}`" );
}

// 2. Delete all cleanshift_* options.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM `{$wpdb->options}` WHERE option_name LIKE %s",
		'cleanshift\_%'
	)
);

// 3. Delete all cleanshift_* transients (both value and timeout entries).
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM `{$wpdb->options}` WHERE option_name LIKE %s OR option_name LIKE %s",
		'\_transient\_cleanshift\_%',
		'\_transient\_timeout\_cleanshift\_%'
	)
);

// Also clean up the rate-limit transients (cs_rl_*).
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM `{$wpdb->options}` WHERE option_name LIKE %s OR option_name LIKE %s",
		'\_transient\_cs\_rl\_%',
		'\_transient\_timeout\_cs\_rl\_%'
	)
);

// 4. Clear the scheduled cron event.
$timestamp = wp_next_scheduled( 'cleanshift_daily_maintenance' );
if ( $timestamp ) {
	wp_unschedule_event( $timestamp, 'cleanshift_daily_maintenance' );
}
