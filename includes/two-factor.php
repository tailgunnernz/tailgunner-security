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
