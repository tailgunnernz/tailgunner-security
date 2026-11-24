<?php
// Tests against a live site with the plugin active:
//   wp eval-file test-site.php
// Only touches throwaway options (tg_security_test*), the ACF list caches it
// restores, and one simulated mail failure. Prints PASS/FAIL lines.

global $wpdb;

// wp eval-file includes this inside a function, so the count lives in
// $GLOBALS rather than a top-level variable.
$GLOBALS['tgt_fails'] = 0;
function tgt( $label, $ok, $detail = '' ) {
	if ( ! $ok ) {
		++$GLOBALS['tgt_fails'];
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $detail ? "  ($detail)" : '' ) . "\n";
}

tgt( 'plugin loaded', defined( 'TG_SECURITY_VERSION' ), defined( 'TG_SECURITY_VERSION' ) ? TG_SECURITY_VERSION : '' );
tgt( 'loaded via mu-plugin loader', function_exists( 'tg_security_loader_current' ) && tg_security_loader_current() );

// Option guard, on throwaway options hooked like the real ones.
if ( wp_using_ext_object_cache() ) {
	$a = 'tg_security_test';
	$b = 'tg_security_test2';
	$c = 'tg_security_test3';
	$d = 'tg_security_test4';
	foreach ( array( $a, $b, $c, $d ) as $o ) {
		delete_option( $o );
		add_filter( "default_option_{$o}", 'tg_security_option_guard', 10, 3 );
	}
	$poison = function ( $name ) {
		$n = wp_cache_get( 'notoptions', 'options' );
		$n = is_array( $n ) ? $n : array();
		$n[ $name ] = true;
		wp_cache_set( 'notoptions', $n, 'options' );
		wp_cache_delete( $name, 'options' );
	};
	// Rows go in directly: reading an option through the API before it
	// exists uses up the guard's one check per option per request.
	$insert = function ( $name, $value ) use ( $wpdb ) {
		$wpdb->insert( $wpdb->options, array( 'option_name' => $name, 'option_value' => $value, 'autoload' => 'off' ) );
	};
	$in_notoptions = function ( $name ) {
		$n = wp_cache_get( 'notoptions', 'options' );
		return is_array( $n ) && isset( $n[ $name ] );
	};

	tgt( 'guard hooked on template', false !== has_filter( 'default_option_template', 'tg_security_option_guard' ) );
	tgt( 'guard hooked on user roles', false !== has_filter( 'default_option_' . $wpdb->prefix . 'user_roles', 'tg_security_option_guard' ) );
	tgt( 'add_option new', true === add_option( $d, 'one', '', false ) );
	tgt( 'add_option existing returns false', false === add_option( $d, 'two', '', false ) );
	$insert( $a, 'one' );
	$heals = (int) ( tg_security_state()['counts']['option_heal'] ?? 0 );
	$poison( $a );
	tgt( 'poisoned option returns real value', 'one' === get_option( $a ) );
	tgt( 'poison removed from notoptions', ! $in_notoptions( $a ) );
	tgt( 'heal recorded', (int) ( tg_security_state()['counts']['option_heal'] ?? 0 ) === $heals + 1 );
	tgt( 'update_option still works', true === update_option( $a, 'three' ) && 'three' === get_option( $a ) );

	$insert( $b, 'bee' );
	$poison( $b );
	$wpdb->ready = false;
	$v           = get_option( $b, 'dflt' );
	$wpdb->ready = true;
	tgt( 'database down returns default', 'dflt' === $v );
	tgt( 'database down leaves no poison', ! $in_notoptions( $b ) );
	tgt( 'database back returns real value', 'bee' === get_option( $b ) );

	tgt( 'missing returns default', 'dflt' === get_option( $c, 'dflt' ) );
	tgt( 'missing stays in notoptions', $in_notoptions( $c ) );

	delete_option( $a );
	delete_option( $b );
	delete_option( $d );
	$n = wp_cache_get( 'notoptions', 'options' );
	unset( $n[ $c ] );
	wp_cache_set( 'notoptions', $n, 'options' );
	// Take the test heal back out of the counts the monitor sees.
	$state = tg_security_state();
	$state['counts']['option_heal'] = $heals;
	if ( ! $heals ) {
		unset( $state['counts']['option_heal'] );
	}
	$state['log']['option_heal']    = array_values( array_filter( (array) ( $state['log']['option_heal'] ?? array() ), function ( $e ) { return 0 !== strpos( $e['option'] ?? '', 'tg_security_test' ); } ) );
	update_option( 'tg_security_state', $state, false );
	tgt( 'option test cleaned up', false === get_option( $a ) && false === get_option( $b ) );
} else {
	echo "SKIP option guard (no persistent object cache)\n";
}

// ACF guard.
if ( wp_using_ext_object_cache() && function_exists( 'acf_get_internal_post_type_posts' ) ) {
	$groups = $wpdb->get_var( "SELECT COUNT(*) FROM $wpdb->posts WHERE post_type = 'acf-field-group' AND post_status IN ('publish','acf-disabled')" );
	if ( $groups ) {
		$key    = acf_cache_key( 'acf_get_field_group_posts' );
		$before = wp_cache_get( $key, 'acf' );
		wp_cache_set( $key, array(), 'acf' );
		wp_cache_delete( 'acf_empty_' . md5( $key ), 'tg_security' );
		$heals = (int) ( tg_security_state()['counts']['acf_heal'] ?? 0 );
		tg_security_acf_guard();
		tgt( 'ACF empty field group list cleared', false === wp_cache_get( $key, 'acf' ) );
		tgt( 'ACF field groups load again', count( acf_get_field_groups() ) > 0 );
		$state = tg_security_state();
		tgt( 'ACF heal recorded', (int) ( $state['counts']['acf_heal'] ?? 0 ) === $heals + 1 );
		$state['counts']['acf_heal'] = $heals;
		if ( ! $heals ) {
			unset( $state['counts']['acf_heal'] );
		}
		array_shift( $state['log']['acf_heal'] );
		update_option( 'tg_security_state', $state, false );
	}
	$empty_types = $wpdb->get_var( "SELECT COUNT(*) FROM $wpdb->posts WHERE post_type = 'acf-ui-options-page'" );
	if ( ! $empty_types ) {
		$key = acf_cache_key( 'acf_get_ui_options_page_posts' );
		wp_cache_set( $key, array(), 'acf' );
		wp_cache_delete( 'acf_empty_' . md5( $key ), 'tg_security' );
		tg_security_acf_guard();
		tgt( 'ACF genuinely empty list kept', array() === wp_cache_get( $key, 'acf' ) );
		tgt( 'ACF empty list marked as checked', (bool) wp_cache_get( 'acf_empty_' . md5( $key ), 'tg_security' ) );
	}
} else {
	echo "SKIP ACF guard\n";
}

// Update policy.
tgt( 'automatic updater not disabled', false === apply_filters( 'automatic_updater_disabled', true ) );
tgt( 'major core updates refused', false === apply_filters( 'allow_major_auto_core_updates', true ) );
tgt( 'minor core updates allowed', true === apply_filters( 'allow_minor_auto_core_updates', false ) );
$next_minor = preg_replace_callback( '/^(\d+\.\d+)(?:\.(\d+))?.*$/', function ( $m ) { return $m[1] . '.' . ( (int) ( $m[2] ?? 0 ) + 1 ); }, get_bloginfo( 'version' ) );
tgt( "auto_update_core true for $next_minor", true === apply_filters( 'auto_update_core', false, (object) array( 'current' => $next_minor ) ) );
tgt( 'auto_update_core false for next major', false === apply_filters( 'auto_update_core', true, (object) array( 'current' => '99.0' ) ) );

// Hardening.
$user_before = get_current_user_id();
wp_set_current_user( 0 );
$response = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/users' ) );
tgt( 'REST users refused when logged out', in_array( $response->get_status(), array( 401, 403 ), true ), (string) $response->get_status() );
$response = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/users/1' ) );
tgt( 'REST single user refused when logged out', in_array( $response->get_status(), array( 401, 403 ), true ), (string) $response->get_status() );
$response = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/posts' ) );
tgt( 'REST posts still public', 200 === $response->get_status(), (string) $response->get_status() );
$admin = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
if ( $admin ) {
	wp_set_current_user( $admin[0]->ID );
	$response = rest_do_request( new WP_REST_Request( 'GET', '/wp/v2/users' ) );
	tgt( 'REST users still work for admins', 200 === $response->get_status(), (string) $response->get_status() );
}
wp_set_current_user( $user_before );
tgt( 'administrator default role becomes subscriber', 'subscriber' === tg_security_safe_default_role( 'administrator' ) );
tgt( 'editor default role becomes subscriber', 'subscriber' === tg_security_safe_default_role( 'editor' ) );
tgt( 'customer default role kept', get_role( 'customer' ) ? 'customer' === tg_security_safe_default_role( 'customer' ) : true );
tgt( 'generator hidden', '' === apply_filters( 'the_generator', '<meta name="generator" content="WordPress">', 'html' ) );
tgt( 'users sitemap off', false === apply_filters( 'wp_sitemaps_add_provider', new stdClass(), 'users' ) );
tgt( 'xmlrpc blocked', tg_security_xmlrpc_blocked() );
tgt( 'theme validation guard passes a healthy site', true === tg_security_validate_theme_guard( true ) );
tgt( 'file editor off', defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT );

// Two-factor.
if ( class_exists( 'Two_Factor_Core' ) && $admin ) {
	$id         = $admin[0]->ID;
	$own        = tg_security_two_factor_own( get_user_meta( $id, '_two_factor_enabled_providers', true ), $id );
	$subscriber = get_users( array( 'role' => 'subscriber', 'number' => 1 ) );

	$prov = Two_Factor_Core::get_enabled_providers_for_user( $admin[0] );
	tgt( 'forced: admin has a second factor', (bool) array_diff( $prov, array( 'Two_Factor_Backup_Codes' ) ), implode( ',', $prov ) );
	if ( ! $own ) {
		tgt( 'forced: admin without own factor gets email', in_array( 'Two_Factor_Email', $prov, true ) );
		tgt( 'forced: status', 'email (forced)' === tg_security_two_factor_status( $id ), tg_security_two_factor_status( $id ) );
	}
	tgt( 'forced: admin is using two-factor', Two_Factor_Core::is_user_using_two_factor( $id ) );
	tgt( 'ticked TOTP without a key does not count', array() === tg_security_two_factor_own( array( 'Two_Factor_Totp' ), $subscriber ? $subscriber[0]->ID : 0 ) || ! $subscriber );
	if ( $subscriber ) {
		tgt( 'forced: subscriber not forced', ! in_array( 'Two_Factor_Email', Two_Factor_Core::get_enabled_providers_for_user( $subscriber[0] ), true ) || in_array( 'Two_Factor_Email', (array) get_user_meta( $subscriber[0]->ID, '_two_factor_enabled_providers', true ), true ) );
	}
} else {
	echo "SKIP two-factor (Two Factor plugin not active)\n";
}

// Mail failure log (simulated, nothing is sent).
$before = (int) ( tg_security_state()['counts']['mail_failed'] ?? 0 );
do_action( 'wp_mail_failed', new WP_Error( 'wp_mail_failed', 'tg-security test: SMTP Error: Could not authenticate. Invalid address: (to): jo.bloggs@example.com', array( 'to' => array( 'a@example.com', 'b@example.com' ), 'subject' => 'Test subject' ) ) );
$state = tg_security_state();
$last  = $state['log']['mail_failed'][0] ?? array();
tgt( 'mail failure counted', (int) ( $state['counts']['mail_failed'] ?? 0 ) === $before + 1 );
tgt( 'mail failure logged', 2 === ( $last['to'] ?? 0 ) && 'Test subject' === ( $last['subject'] ?? '' ) && false !== strpos( $last['error'] ?? '', 'Could not authenticate' ) );
tgt( 'mail failure address redacted', false !== strpos( $last['error'] ?? '', '***@example.com' ) && false === strpos( $last['error'] ?? '', 'jo.bloggs' ), $last['error'] ?? '' );
$state['counts']['mail_failed'] = $before;
array_shift( $state['log']['mail_failed'] );
if ( ! $state['log']['mail_failed'] ) {
	unset( $state['log']['mail_failed'] );
}
if ( ! $before ) {
	unset( $state['counts']['mail_failed'] );
}
update_option( 'tg_security_state', $state, false );

// Health check with a throwaway key.
$kp = sodium_crypto_sign_keypair();
add_filter( 'tg_security_health_keys', function () use ( $kp ) { return array( base64_encode( sodium_crypto_sign_publickey( $kp ) ) ); } );
$last_ts = get_option( 'tg_security_health_last' );
$ts      = (int) floor( microtime( true ) * 1000 );
$body    = wp_json_encode( array( 'host' => wp_parse_url( home_url(), PHP_URL_HOST ), 'ts' => $ts ) );
$sig     = base64_encode( sodium_crypto_sign_detached( $body, sodium_crypto_sign_secretkey( $kp ) ) );
tgt( 'health signature verifies', true === tg_security_health_verify( $body, $sig ) );
tgt( 'health replay refused', 'replay' === tg_security_health_verify( $body, $sig ) );
false === $last_ts ? delete_option( 'tg_security_health_last' ) : update_option( 'tg_security_health_last', $last_ts, false );

$report = tg_security_health_report();
tgt( 'health report has admins', ! empty( $report['users']['admins'] ) );
tgt( 'health report has roles hash', 32 === strlen( $report['users']['roles_hash'] ) );
tgt( 'health admins include every manage_options user', count( $report['users']['admins'] ) >= count( get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) ) ) );
tgt( 'health report theme valid', ! $report['site']['theme_errors'], implode( ',', $report['site']['theme_errors'] ) );
echo 'health warnings: ', $report['warnings'] ? implode( ', ', $report['warnings'] ) : 'none', "\n";

// Scanner patterns.
tgt( 'scanner blocks /.env', tg_security_scanner_blocked( tg_security_scanner_path( '/.env', wp_parse_url( home_url(), PHP_URL_PATH ) ) ) );
tgt( 'scanner allows /', ! tg_security_scanner_blocked( tg_security_scanner_path( '/', wp_parse_url( home_url(), PHP_URL_PATH ) ) ) );

echo $GLOBALS['tgt_fails'] ? "\n{$GLOBALS['tgt_fails']} FAILED\n" : "\nall passed\n";
