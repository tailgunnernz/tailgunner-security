<?php
/**
 * Forced two-factor, for sites running the Two Factor plugin.
 *
 * Anyone who can manage the site, edit other people's content or run the
 * shop must use a second factor. If they haven't set one up, they get codes
 * by email. When someone has an authenticator app (or a passkey) and left
 * their primary method on "Default", that is used before email.
 *
 * Without the Two Factor plugin this does nothing; the health check reports
 * the plugin as missing. To switch forcing off on one site, return false for
 * 'two_factor' from the tg_security_feature_enabled filter in an mu-plugin.
 */

defined( 'ABSPATH' ) || exit;

function tg_security_two_factor_required( $user_id ) {
	return user_can( $user_id, 'manage_options' )
		|| user_can( $user_id, 'edit_others_posts' )
		|| user_can( $user_id, 'manage_woocommerce' );
}

/**
 * Providers the user has actually set up. A method that is ticked but never
 * configured (an authenticator app with no secret saved) doesn't count, and
 * neither do backup codes, which are a fallback.
 */
function tg_security_two_factor_own( $providers, $user_id ) {
	$keys = array_filter(
		(array) $providers,
		function ( $key ) {
			return is_string( $key ) && '' !== $key && ! in_array( $key, array( 'Two_Factor_Backup_Codes', 'Two_Factor_Dummy' ), true );
		}
	);

	if ( ! $keys || ! class_exists( 'Two_Factor_Core' ) || ! method_exists( 'Two_Factor_Core', 'get_supported_providers_for_user' ) ) {
		return array_values( $keys );
	}

	$user = get_userdata( $user_id );

	if ( ! $user ) {
		return array();
	}

	$supported = Two_Factor_Core::get_supported_providers_for_user( $user );
	$own       = array();

	foreach ( $keys as $key ) {
		if ( isset( $supported[ $key ] ) && is_object( $supported[ $key ] ) && method_exists( $supported[ $key ], 'is_available_for_user' ) && $supported[ $key ]->is_available_for_user( $user ) ) {
			$own[] = $key;
		}
	}

	return $own;
}

function tg_security_two_factor_meta_key() {
	return defined( 'Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY' ) ? Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY : '_two_factor_enabled_providers';
}

function tg_security_force_two_factor( $providers, $user_id ) {
	static $busy = false;

	if ( $busy || ! class_exists( 'Two_Factor_Core' ) || ! tg_security_enabled( 'two_factor' ) ) {
		return $providers;
	}

	$providers = is_array( $providers ) ? $providers : array();

	if ( ! tg_security_two_factor_required( $user_id ) ) {
		return $providers;
	}

	// A third-party provider's availability check may read the enabled list.
	$busy = true;
	$own  = tg_security_two_factor_own( $providers, $user_id );
	$busy = false;

	if ( ! $own && ! in_array( 'Two_Factor_Email', $providers, true ) ) {
		$providers[] = 'Two_Factor_Email';
	}

	return $providers;
}

function tg_security_two_factor_primary( $provider, $user_id ) {
	if ( ! class_exists( 'Two_Factor_Core' ) || ! tg_security_enabled( 'two_factor' ) ) {
		return $provider;
	}

	$meta_key = defined( 'Two_Factor_Core::PROVIDER_USER_META_KEY' ) ? Two_Factor_Core::PROVIDER_USER_META_KEY : '_two_factor_provider';

	// The user picked a primary method themselves.
	if ( get_user_meta( $user_id, $meta_key, true ) ) {
		return $provider;
	}

	$user = get_userdata( $user_id );

	if ( ! $user || ! method_exists( 'Two_Factor_Core', 'get_available_providers_for_user' ) ) {
		return $provider;
	}

	$available = Two_Factor_Core::get_available_providers_for_user( $user );

	foreach ( array( 'Two_Factor_Totp', 'TwoFactor_Provider_WebAuthn' ) as $preferred ) {
		if ( isset( $available[ $preferred ] ) ) {
			return $preferred;
		}
	}

	return $provider;
}

/**
 * For the health check: what login will ask this user for.
 */
function tg_security_two_factor_status( $user_id ) {
	if ( ! class_exists( 'Two_Factor_Core' ) ) {
		return 'none';
	}

	$own = tg_security_two_factor_own( get_user_meta( $user_id, tg_security_two_factor_meta_key(), true ), $user_id );

	if ( $own ) {
		return implode( ',', $own );
	}

	if ( ! tg_security_enabled( 'two_factor' ) || ! tg_security_two_factor_required( $user_id ) ) {
		return 'none';
	}

	return 'email (forced)';
}

/**
 * Two Factor 0.8.0 to 0.16.0 deletes a user's pending login nonce whenever the
 * value sent to wp-login.php?action=validate_2fa doesn't match it. That request
 * needs no authentication, so anyone can cancel someone else's half-finished
 * two-factor login by sending a wrong value with their user ID
 * (CVE-2026-100508). Two Factor 0.17.0 keeps the pending nonce on a mismatch
 * and only clears an expired one, but needs WordPress 7.0.
 *
 * This applies the 0.17.0 rule to the older versions. When the user has a live
 * nonce and the value sent doesn't match it, the request gets the same
 * redirect Two Factor gives any failed check, and the stored nonce stays. A
 * matching value, an expired nonce or no nonce at all goes on to Two Factor
 * unchanged. The comparison uses Two Factor's own hashing; if that can't be
 * called, the request is left to Two Factor.
 *
 * Runs on login_form_validate_2fa before Two Factor's handler. It only reads,
 * so a flood of wrong values writes nothing to the database.
 */
function tg_security_two_factor_nonce_hook() {
	if ( tg_security_two_factor_nonce_unguarded() ) {
		add_action( 'login_form_validate_2fa', 'tg_security_two_factor_nonce_guard', 1 );
	}
}

function tg_security_two_factor_nonce_guard() {
	if ( ! tg_security_enabled( 'two_factor_nonce' ) || ! tg_security_two_factor_nonce_unguarded() ) {
		return;
	}

	// Read the request the way Two Factor 0.8.0 to 0.16.0 does.
	// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput
	$user_id = ! empty( $_REQUEST['wp-auth-id'] ) ? absint( $_REQUEST['wp-auth-id'] ) : 0;
	$nonce   = ! empty( $_REQUEST['wp-auth-nonce'] ) ? wp_unslash( $_REQUEST['wp-auth-nonce'] ) : '';
	// phpcs:enable
	$user = $user_id ? get_user_by( 'id', $user_id ) : false;

	if ( ! $user || ! $nonce ) {
		return;
	}

	$meta_key = defined( 'Two_Factor_Core::USER_META_NONCE_KEY' ) ? Two_Factor_Core::USER_META_NONCE_KEY : '_two_factor_nonce';
	$stored   = get_user_meta( $user->ID, $meta_key, true );

	if ( ! is_array( $stored ) || empty( $stored['key'] ) || ! is_string( $stored['key'] ) || empty( $stored['expiration'] ) || ! is_numeric( $stored['expiration'] ) || time() >= (int) $stored['expiration'] ) {
		return;
	}

	// The same array, in the same order, that Two Factor hashes.
	$hash = tg_security_two_factor_nonce_hash(
		array(
			'user_id'    => $user->ID,
			'expiration' => $stored['expiration'],
			'key'        => $nonce,
		)
	);

	if ( null === $hash || ( is_string( $hash ) && '' !== $hash && hash_equals( $stored['key'], $hash ) ) ) {
		return;
	}

	wp_safe_redirect( home_url() );
	exit;
}

/**
 * True when the running Two Factor still deletes a live nonce on a mismatch
 * and hashes nonces the way this guard expects (0.8.0 onwards; 0.7.x has the
 * same flaw but a different scheme and isn't covered). Pre-releases of 0.17.0
 * already have the fix.
 */
function tg_security_two_factor_nonce_unguarded() {
	return defined( 'TWO_FACTOR_VERSION' ) && is_string( TWO_FACTOR_VERSION )
		&& version_compare( TWO_FACTOR_VERSION, '0.8.0', '>=' ) && version_compare( TWO_FACTOR_VERSION, '0.17.0-dev', '<' )
		&& class_exists( 'Two_Factor_Core', false ) && method_exists( 'Two_Factor_Core', 'hash_login_nonce' );
}

/**
 * Two Factor's own login nonce hash (a protected method), or null when it
 * can't be called. False from Two Factor (the value wouldn't encode) is
 * returned as false: a genuine nonce always encodes, so that's a mismatch.
 */
function tg_security_two_factor_nonce_hash( $nonce ) {
	try {
		$method = new ReflectionMethod( 'Two_Factor_Core', 'hash_login_nonce' );
		if ( ! $method->isStatic() ) {
			return null;
		}
		if ( PHP_VERSION_ID < 80100 ) {
			$method->setAccessible( true );
		}
		return $method->invoke( null, $nonce );
	} catch ( Throwable $e ) {
		return null;
	}
}
