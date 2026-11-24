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
