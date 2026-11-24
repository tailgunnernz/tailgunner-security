<?php
/**
 * Shared helpers: the per-feature switch and the event log the health check
 * reports from.
 */

defined( 'ABSPATH' ) || exit;

/**
 * Every feature is on. A site that needs an exception turns one off in an
 * mu-plugin (some features run before themes and normal plugins load):
 *
 *     add_filter( 'tg_security_feature_enabled', function ( $on, $feature ) {
 *         return 'headers' === $feature ? false : $on;
 *     }, 10, 2 );
 *
 * Features: option_guard, acf_guard, scanner_block, update_policy,
 * two_factor, xmlrpc, file_editor, user_enumeration, default_role,
 * hide_version, headers, mail_log, health.
 */
function tg_security_enabled( $feature ) {
	return (bool) apply_filters( 'tg_security_feature_enabled', true, $feature );
}

/**
 * The plugin's basename (folder/tailgunner-security.php), known even when
 * only early.php has loaded.
 */
function tg_security_basename() {
	return basename( TG_SECURITY_DIR ) . '/tailgunner-security.php';
}

/**
 * Puts the plugin back in active_plugins when the mu-plugin loader is running
 * it but WordPress has it switched off and nobody deactivated it.
 *
 * Deactivating through WordPress removes the loader and leaves a tombstone, so
 * this only fires when the plugin dropped out of the list some other way: an
 * object cache serving a stale active_plugins while another plugin saved the
 * list, for example. At most once an hour. Deleting the plugin folder still
 * switches everything off, because the loader then has nothing to include.
 */
function tg_security_maybe_reactivate() {
	if ( ! defined( 'TG_SECURITY_LOADER' ) || defined( 'TG_SECURITY_FILE' ) || is_multisite() || wp_installing() || wp_is_maintenance_mode() ) {
		return;
	}

	$basename = tg_security_basename();

	if ( file_exists( WPMU_PLUGIN_DIR . '/0-tailgunner-security.php.off' ) || ! is_readable( WP_PLUGIN_DIR . '/' . $basename ) || get_transient( 'tg_security_reactivated' ) ) {
		return;
	}

	$active = get_option( 'active_plugins' );

	// An empty or broken list is the option guard's job. A plugin that is in
	// the list but didn't load is paused by recovery mode: leave it.
	if ( ! is_array( $active ) || ! $active || in_array( $basename, $active, true ) ) {
		return;
	}

	set_transient( 'tg_security_reactivated', 1, HOUR_IN_SECONDS );

	$active[] = $basename;
	sort( $active );
	update_option( 'active_plugins', $active );

	tg_security_record( 'reactivated' );
}

function tg_security_is_web_request() {
	return 'cli' !== PHP_SAPI && ! ( defined( 'WP_CLI' ) && WP_CLI );
}

function tg_security_clip( $text, $length ) {
	$text = trim( preg_replace( '/\s+/', ' ', wp_strip_all_tags( (string) $text ) ) );

	if ( function_exists( 'mb_substr' ) ) {
		return mb_substr( $text, 0, $length );
	}

	return substr( $text, 0, $length );
}

/**
 * The state option: a running count per event type and the last few events
 * of each type, so a burst of mail failures can't push guard heals out.
 */
function tg_security_state() {
	$state = get_option( 'tg_security_state' );

	if ( ! is_array( $state ) ) {
		$state = array();
	}

	return array_merge( array( 'counts' => array(), 'log' => array() ), $state );
}

function tg_security_record( $type, array $detail = array() ) {
	$state = tg_security_state();

	$state['counts'][ $type ] = ( isset( $state['counts'][ $type ] ) ? (int) $state['counts'][ $type ] : 0 ) + 1;

	$log = isset( $state['log'][ $type ] ) && is_array( $state['log'][ $type ] ) ? $state['log'][ $type ] : array();
	array_unshift( $log, array( 't' => time() ) + $detail );
	$state['log'][ $type ] = array_slice( $log, 0, 20 );

	update_option( 'tg_security_state', $state, false );
}

/**
 * How many events of a type happened in the last $seconds, as far as the
 * 20-entry log goes back.
 */
function tg_security_recent( $type, $seconds = DAY_IN_SECONDS ) {
	$state = tg_security_state();
	$since = time() - $seconds;
	$count = 0;

	if ( empty( $state['log'][ $type ] ) || ! is_array( $state['log'][ $type ] ) ) {
		return 0;
	}

	foreach ( $state['log'][ $type ] as $event ) {
		if ( isset( $event['t'] ) && $event['t'] >= $since ) {
			++$count;
		}
	}

	return $count;
}
