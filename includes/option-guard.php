<?php
/**
 * Option cache guard.
 *
 * When the database drops out (a MariaDB OOM restart, say), a persistent
 * object cache such as Object Cache Pro can record core options as missing
 * in `notoptions` and keep serving that after the database is back. With
 * `template` missing, pages come out blank.
 *
 * When one of these options reads as missing, the guard asks the database
 * directly. If the row is there, it clears the options cache and returns the
 * real value. If the database can't answer, it drops the unconfirmed
 * "missing" so the next request tries again.
 */

defined( 'ABSPATH' ) || exit;

function tg_security_option_guard_names() {
	global $wpdb;

	return array_merge(
		array(
			'siteurl',
			'home',
			'active_plugins',
			'template',
			'stylesheet',
			'blog_charset',
			'db_version',           // Missing sends wp-admin to the database upgrade screen.
			'cron',                 // Missing, the next scheduled event overwrites every other one.
			'permalink_structure',
			'show_on_front',
			'page_on_front',
			$wpdb->prefix . 'user_roles', // Missing, every user loses their role.
		),
		array_keys( tg_security_option_guard_requires() )
	);
}

/**
 * Plugin options guarded only while that plugin is loaded. Other plugins read
 * `woocommerce_version` to detect WooCommerce, so guarding it everywhere
 * would cost a query on every site without it.
 */
function tg_security_option_guard_requires() {
	return array(
		'woocommerce_version'    => 'WooCommerce', // Missing reruns the WooCommerce installer.
		'woocommerce_db_version' => 'WooCommerce',
		'gf_db_version'          => 'GFForms',
		'rg_form_version'        => 'GFForms',
	);
}

function tg_security_option_guard( $default_value, $option, $passed_default = false ) {
	global $wpdb;
	static $checked = array();

	if ( isset( $checked[ $option ] ) || wp_installing() || ! wp_using_ext_object_cache() ) {
		return $default_value;
	}

	$notoptions = wp_cache_get( 'notoptions', 'options' );

	if ( ! is_array( $notoptions ) || ! isset( $notoptions[ $option ] ) ) {
		return $default_value;
	}

	$requires = tg_security_option_guard_requires();

	if ( isset( $requires[ $option ] ) && ! class_exists( $requires[ $option ], false ) ) {
		return $default_value;
	}

	if ( ! tg_security_enabled( 'option_guard' ) ) {
		return $default_value;
	}

	$checked[ $option ] = true;

	$suppress = $wpdb->suppress_errors();
	$row      = $wpdb->get_row( $wpdb->prepare( "SELECT option_value FROM $wpdb->options WHERE option_name = %s LIMIT 1", $option ) );
	$failed   = ! $wpdb->ready || '' !== $wpdb->last_error;
	$wpdb->suppress_errors( $suppress );

	if ( ! is_object( $row ) ) {
		if ( $failed ) {
			// Couldn't confirm it's missing, so don't keep caching that it is.
			unset( $notoptions[ $option ] );
			wp_cache_set( 'notoptions', $notoptions, 'options' );

			// Without these the page comes out blank or on the wrong theme,
			// and a page cache or CDN would keep that copy. A 503 isn't cached
			// and tells visitors and search engines to come back.
			if ( tg_security_is_web_request() && in_array( $option, array( 'siteurl', 'home', 'active_plugins', 'template', 'stylesheet' ), true ) ) {
				tg_security_option_guard_unavailable();
			}
		}

		return $default_value;
	}

	// The cached "missing" was false, so the rest of the options cache from
	// the same outage can't be trusted either. Reload all of it.
	wp_cache_delete( 'notoptions', 'options' );
	wp_cache_delete( 'alloptions', 'options' );
	wp_cache_set( $option, $row->option_value, 'options' );

	error_log( "tailgunner-security: option '{$option}' was cached as missing; options cache reset" );
	tg_security_record( 'option_heal', array( 'option' => $option ) );

	// This request may already have read a missing siteurl (WordPress does,
	// before any plugin loads), so keep its page out of page caches.
	if ( ! defined( 'DONOTCACHEPAGE' ) ) {
		define( 'DONOTCACHEPAGE', true );
	}
	add_action( 'send_headers', 'nocache_headers' );

	return $passed_default ? get_option( $option, $default_value ) : get_option( $option );
}

function tg_security_option_guard_unavailable() {
	if ( ! headers_sent() ) {
		status_header( 503 );
		nocache_headers();
		header( 'Retry-After: 30' );
		header( 'Content-Type: text/plain; charset=utf-8' );
	}

	echo 'This site is temporarily unavailable. Please try again in a minute.';
	exit;
}

/**
 * WordPress switches to a default theme when the active one looks broken,
 * which it checks on the Themes screen and in the Customizer. A stale cache
 * makes a healthy theme look broken, so the theme options are checked
 * against the database first. If they disagree, or the database can't answer, the check
 * is skipped and the cache reset.
 */
function tg_security_validate_theme_guard( $validate ) {
	global $wpdb;

	if ( ! $validate || ! tg_security_enabled( 'option_guard' ) ) {
		return $validate;
	}

	$suppress = $wpdb->suppress_errors();
	$rows     = $wpdb->get_results( "SELECT option_name, option_value FROM $wpdb->options WHERE option_name IN ( 'template', 'stylesheet' )", OBJECT_K );
	$failed   = ! $wpdb->ready || '' !== $wpdb->last_error;
	$wpdb->suppress_errors( $suppress );

	if ( $failed ) {
		return false;
	}

	foreach ( array( 'template', 'stylesheet' ) as $name ) {
		$stored = isset( $rows[ $name ] ) ? (string) $rows[ $name ]->option_value : '';

		if ( '' !== $stored && get_option( $name ) !== $stored ) {
			wp_cache_delete( 'notoptions', 'options' );
			wp_cache_delete( 'alloptions', 'options' );
			wp_cache_delete( $name, 'options' );

			error_log( "tailgunner-security: option '{$name}' didn't match the database at theme validation; skipped it and reset the options cache" );
			tg_security_record( 'option_heal', array( 'option' => $name, 'via' => 'validate_current_theme' ) );

			return false;
		}
	}

	return $validate;
}
