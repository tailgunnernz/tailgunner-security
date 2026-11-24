<?php
/**
 * Health check for monitor.tailgunner.co.nz.
 *
 * The monitor POSTs to https://<site>/?tailgunner-health with a small JSON
 * body, {"host":"example.co.nz","ts":<unix ms>}, signed with its Ed25519
 * private key in the X-Tailgunner-Signature header (base64). The plugin only
 * holds the public key, so the public repo gives nothing away and no site
 * needs its own secret. Each timestamp is accepted once.
 *
 * The answer covers what a plain status check misses: core settings that read
 * as missing, an invalid theme, guard heals, mail failures, administrator
 * accounts (the monitor diffs them between checks), two-factor coverage,
 * overdue cron, pending updates and update settings that disagree with
 * the policy.
 */

defined( 'ABSPATH' ) || exit;

/**
 * Public keys allowed to sign health checks. Rotate by adding the new key,
 * moving the monitor over, then removing the old one.
 */
function tg_security_health_keys() {
	return (array) apply_filters(
		'tg_security_health_keys',
		array(
			'dTmtT44JJb5+X+CFFhcagKnhZkSga+QCoJ8O+mnGfng=',
		)
	);
}

function tg_security_health_maybe_serve() {
	if ( ! isset( $_GET['tailgunner-health'] ) || ! tg_security_is_web_request() || ! tg_security_enabled( 'health' ) ) {
		return;
	}

	nocache_headers();
	header( 'Content-Type: application/json; charset=utf-8' );
	header( 'X-Robots-Tag: noindex' );

	if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== $_SERVER['REQUEST_METHOD'] ) {
		status_header( 405 );
		echo '{"error":"method"}';
		exit;
	}

	$body  = (string) file_get_contents( 'php://input', false, null, 0, 2048 );
	$sig   = isset( $_SERVER['HTTP_X_TAILGUNNER_SIGNATURE'] ) ? (string) $_SERVER['HTTP_X_TAILGUNNER_SIGNATURE'] : '';
	$check = tg_security_health_verify( $body, $sig );

	if ( true !== $check ) {
		status_header( 403 );
		echo wp_json_encode( array( 'error' => $check ) );
		exit;
	}

	status_header( 200 );
	echo wp_json_encode( tg_security_health_report(), JSON_UNESCAPED_SLASHES );
	exit;
}

/**
 * Returns true, or a short reason the request was refused.
 */
function tg_security_health_verify( $body, $signature, $now_ms = null ) {
	if ( '' === $body || strlen( $body ) > 1024 ) {
		return 'body';
	}

	$signature = base64_decode( trim( $signature ), true );

	if ( false === $signature || 64 !== strlen( $signature ) ) {
		return 'signature';
	}

	if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) && is_readable( ABSPATH . WPINC . '/sodium_compat/autoload.php' ) ) {
		require_once ABSPATH . WPINC . '/sodium_compat/autoload.php';
	}

	if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
		return 'sodium';
	}

	$valid = false;

	foreach ( tg_security_health_keys() as $key ) {
		$key = base64_decode( (string) $key, true );

		if ( false === $key || 32 !== strlen( $key ) ) {
			continue;
		}

		try {
			if ( sodium_crypto_sign_verify_detached( $signature, $body, $key ) ) {
				$valid = true;
				break;
			}
		} catch ( Throwable $e ) {
			continue;
		}
	}

	if ( ! $valid ) {
		return 'signature';
	}

	$request = json_decode( $body, true );

	if ( ! is_array( $request ) || empty( $request['host'] ) || ! is_string( $request['host'] ) || ! isset( $request['ts'] ) || ! is_int( $request['ts'] ) ) {
		return 'payload';
	}

	$now_ms = null === $now_ms ? (int) floor( microtime( true ) * 1000 ) : (int) $now_ms;

	if ( abs( $now_ms - $request['ts'] ) > 5 * MINUTE_IN_SECONDS * 1000 ) {
		return 'clock';
	}

	if ( ! tg_security_health_host_matches( $request['host'] ) ) {
		return 'host';
	}

	// Each signed request works once: the timestamp has to move forward.
	if ( $request['ts'] <= (int) get_option( 'tg_security_health_last', 0 ) ) {
		return 'replay';
	}

	update_option( 'tg_security_health_last', $request['ts'], false );

	return true;
}

function tg_security_health_host_matches( $host ) {
	$normalise = function ( $value ) {
		$value = strtolower( trim( (string) $value ) );
		$value = preg_replace( '/:\d+$/', '', $value );

		return preg_replace( '/^www\./', '', $value );
	};

	$host = $normalise( $host );

	foreach ( array( home_url(), site_url() ) as $url ) {
		if ( '' !== $host && $normalise( wp_parse_url( $url, PHP_URL_HOST ) ) === $host ) {
			return true;
		}
	}

	return false;
}

function tg_security_health_report() {
	global $wpdb;

	$warnings = array();
	$state    = tg_security_state();

	// Core settings. Reading them also gives the option guard its chance to
	// heal, which then shows up in the guard section.
	$options = array();

	foreach ( array( 'siteurl', 'home', 'template', 'stylesheet', 'blog_charset' ) as $name ) {
		$value            = get_option( $name );
		$options[ $name ] = is_string( $value ) ? $value : '';

		if ( '' === $options[ $name ] ) {
			$warnings[] = 'option_missing:' . $name;
		}
	}

	$active_plugins = get_option( 'active_plugins' );

	if ( ! is_array( $active_plugins ) || ! $active_plugins ) {
		$warnings[] = 'option_missing:active_plugins';
	}

	// Guarded options the cache still records as missing. A plugin's option
	// only counts while that plugin is loaded.
	$notoptions = wp_cache_get( 'notoptions', 'options' );
	$requires   = tg_security_option_guard_requires();
	$poisoned   = array();

	if ( is_array( $notoptions ) ) {
		foreach ( tg_security_option_guard_names() as $name ) {
			if ( isset( $notoptions[ $name ] ) && ( ! isset( $requires[ $name ] ) || class_exists( $requires[ $name ], false ) ) ) {
				$poisoned[] = $name;
			}
		}
	}

	// Theme, checked the way validate_current_theme() does before it falls
	// back to a default theme.
	$theme_errors = array();

	// A blank template points get_template_directory() at the themes folder,
	// whose index.php exists, so check for that first.
	if ( '' === get_template() || '' === get_stylesheet() ) {
		$theme_errors[] = 'theme_option_empty';
	} elseif ( ! file_exists( get_template_directory() . '/index.php' ) && ! file_exists( get_template_directory() . '/templates/index.html' ) ) {
		$theme_errors[] = 'template_index';
	}

	if ( ! $theme_errors && ! file_exists( get_template_directory() . '/style.css' ) ) {
		$theme_errors[] = 'template_style';
	}

	if ( ! $theme_errors && get_stylesheet() !== get_template() && ! file_exists( get_stylesheet_directory() . '/style.css' ) ) {
		$theme_errors[] = 'stylesheet_style';
	}

	if ( $theme_errors ) {
		$warnings[] = 'theme_invalid';
	}

	// The plugin and its loader.
	$main_file      = TG_SECURITY_DIR . 'tailgunner-security.php';
	$plugin_active  = is_array( $active_plugins ) && in_array( plugin_basename( $main_file ), $active_plugins, true );
	$loader_current = function_exists( 'tg_security_loader_current' ) ? tg_security_loader_current() : defined( 'TG_SECURITY_LOADER' );

	if ( ! $plugin_active ) {
		$warnings[] = 'plugin_inactive';
	}

	if ( ! $loader_current ) {
		$warnings[] = 'loader_missing';
	}

	// Cron. Judged by when it last ran, not by the oldest event: some plugins
	// (the update checker in this one, for a start) schedule their first run
	// in the past on purpose. A site with no heartbeat yet gets an hour from
	// its first health check.
	$crons      = function_exists( '_get_cron_array' ) ? _get_cron_array() : array();
	$oldest_due = 0;

	if ( is_array( $crons ) && $crons ) {
		$oldest_due = max( 0, time() - (int) min( array_keys( $crons ) ) );
	}

	$cron_last = (int) get_option( 'tg_security_cron_last' );

	if ( ! $cron_last ) {
		$cron_last = time();
		add_option( 'tg_security_cron_last', $cron_last, '', false );
	}

	$cron_since = max( 0, time() - $cron_last );

	if ( $cron_since > HOUR_IN_SECONDS && $oldest_due > HOUR_IN_SECONDS ) {
		$warnings[] = 'cron_overdue';
	}

	// Updates.
	$core_update = null;
	$core        = get_site_transient( 'update_core' );

	if ( is_object( $core ) && ! empty( $core->updates ) ) {
		foreach ( (array) $core->updates as $offer ) {
			if ( is_object( $offer ) && isset( $offer->response ) && 'upgrade' === $offer->response ) {
				$core_update = $offer->current;
				break;
			}
		}
	}

	$plugin_updates = get_site_transient( 'update_plugins' );
	$theme_updates  = get_site_transient( 'update_themes' );
	$auto_disabled  = null;

	if ( ! class_exists( 'WP_Automatic_Updater' ) && is_readable( ABSPATH . 'wp-admin/includes/class-wp-automatic-updater.php' ) ) {
		require_once ABSPATH . 'wp-admin/includes/class-wp-automatic-updater.php';
	}

	if ( class_exists( 'WP_Automatic_Updater' ) ) {
		$auto_disabled = ( new WP_Automatic_Updater() )->is_disabled();
	}

	if ( $auto_disabled ) {
		$warnings[] = 'auto_updates_disabled';
	}

	// Privileged accounts: anyone who can change settings, users, plugins or
	// themes, whether through a role or a capability given to them directly.
	// The monitor diffs this list between checks. Queries skip the cache so a
	// new account shows up straight away.
	$admins = array();

	foreach (
		get_users(
			array(
				'capability__in' => array( 'manage_options', 'promote_users', 'edit_users', 'create_users', 'delete_users', 'install_plugins', 'activate_plugins', 'edit_plugins', 'install_themes', 'edit_themes', 'update_core' ),
				'orderby'        => 'ID',
				'cache_results'  => false,
			)
		) as $user
	) {
		$roles = array_values( (array) $user->roles );

		$admins[] = array(
			'id'         => (int) $user->ID,
			'login'      => $user->user_login,
			'email'      => $user->user_email,
			'registered' => $user->user_registered,
			'roles'      => $roles,
			'extra_caps' => array_values( array_diff( array_keys( array_filter( (array) $user->caps ) ), $roles ) ),
			'two_factor' => tg_security_two_factor_status( $user->ID ),
		);
	}

	// Two-factor.
	$two_factor_plugin = class_exists( 'Two_Factor_Core' );
	$two_factor_forced = $two_factor_plugin && tg_security_enabled( 'two_factor' );

	if ( ! $two_factor_plugin && tg_security_enabled( 'two_factor' ) ) {
		$warnings[] = 'two_factor_plugin_missing';
	}

	$editors = array();

	foreach (
		get_users(
			array(
				'capability__in' => array( 'edit_others_posts', 'manage_woocommerce' ),
				'exclude'        => wp_list_pluck( $admins, 'id' ),
				'fields'         => array( 'ID', 'user_login' ),
				'cache_results'  => false,
			)
		) as $user
	) {
		$editors[] = array(
			'login'      => $user->user_login,
			'two_factor' => tg_security_two_factor_status( $user->ID ),
		);
	}

	// A hash of the role definitions, so the monitor sees a role quietly
	// given more capabilities.
	$roles_hash = md5( (string) maybe_serialize( get_option( $wpdb->prefix . 'user_roles' ) ) );

	// Registration.
	$raw_default_role = $wpdb->get_var( "SELECT option_value FROM $wpdb->options WHERE option_name = 'default_role' LIMIT 1" );

	if ( $raw_default_role && 'subscriber' !== $raw_default_role && 'subscriber' === tg_security_safe_default_role( $raw_default_role ) ) {
		$warnings[] = 'default_role_privileged';
	}

	// Mail and guard events.
	$mail_recent = tg_security_recent( 'mail_failed' );

	if ( $mail_recent ) {
		$warnings[] = 'mail_failed_24h';
	}

	foreach ( array( 'option_heal', 'acf_heal' ) as $type ) {
		if ( tg_security_recent( $type ) ) {
			$warnings[] = $type . '_24h';
		}
	}

	$log = function ( $type, $count = 5 ) use ( $state ) {
		return isset( $state['log'][ $type ] ) ? array_slice( (array) $state['log'][ $type ], 0, $count ) : array();
	};

	return array(
		'ok'       => ! $warnings,
		'warnings' => $warnings,
		'time'     => time(),
		'plugin'   => array(
			'version' => TG_SECURITY_VERSION,
			'active'  => $plugin_active,
			'loader'  => $loader_current,
		),
		'site'     => array(
			'wp'             => get_bloginfo( 'version' ),
			'php'            => PHP_VERSION,
			'db'             => $wpdb->db_server_info(),
			'object_cache'   => wp_using_ext_object_cache(),
			'multisite'      => is_multisite(),
			'options'        => $options,
			'active_plugins' => is_array( $active_plugins ) ? count( $active_plugins ) : 0,
			'notoptions'     => $poisoned,
			'theme_errors'   => $theme_errors,
		),
		'cron'     => array(
			'wp_cron_disabled' => defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON,
			'last_run_seconds' => $cron_since,
			'oldest_due_seconds' => $oldest_due,
		),
		'updates'  => array(
			'core'                 => $core_update,
			'plugins'              => is_object( $plugin_updates ) && ! empty( $plugin_updates->response ) ? count( (array) $plugin_updates->response ) : 0,
			'themes'               => is_object( $theme_updates ) && ! empty( $theme_updates->response ) ? count( (array) $theme_updates->response ) : 0,
			'last_checked'         => is_object( $core ) && isset( $core->last_checked ) ? (int) $core->last_checked : null,
			'auto_updates_disabled' => $auto_disabled,
			'policy_conflicts'     => tg_security_update_conflicts(),
		),
		'users'    => array(
			'admins'             => $admins,
			'editors'            => $editors,
			'roles_hash'         => $roles_hash,
			'two_factor_plugin'  => $two_factor_plugin,
			'two_factor_forced'  => $two_factor_forced,
			'users_can_register' => (bool) get_option( 'users_can_register' ),
			'default_role'       => $raw_default_role,
		),
		'hardening' => array(
			'xmlrpc_blocked'     => tg_security_xmlrpc_blocked(),
			'file_editor_off'    => defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT,
			'headers'            => tg_security_enabled( 'headers' ),
			'scanner_block'      => tg_security_enabled( 'scanner_block' ),
		),
		'events'   => array(
			'counts'       => $state['counts'],
			'mail_24h'     => $mail_recent,
			'mail_failed'  => $log( 'mail_failed' ),
			'option_heal'  => $log( 'option_heal' ),
			'acf_heal'     => $log( 'acf_heal' ),
			'loader_failed' => $log( 'loader_failed', 1 ),
		),
	);
}

/**
 * Notes when WP-Cron last ran, from wp-cron.php or `wp cron event run`, at
 * most once a minute.
 */
function tg_security_cron_heartbeat() {
	if ( time() - (int) get_option( 'tg_security_cron_last' ) >= MINUTE_IN_SECONDS ) {
		update_option( 'tg_security_cron_last', time(), false );
	}
}
