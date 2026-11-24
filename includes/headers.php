<?php
/**
 * Security headers, for hosts where we can't set them in the server config:
 * HSTS (short max-age, no includeSubDomains or preload, as we don't know what
 * subdomains clients run), nosniff, Referrer-Policy, and frame protection on
 * front-end pages. No Content-Security-Policy: that is the header that breaks
 * sites.
 *
 * A header already set by something else is left as it is. Pages a cache
 * serves without running PHP only get these once the cache refreshes.
 */

defined( 'ABSPATH' ) || exit;

function tg_security_hsts_max_age() {
	return DAY_IN_SECONDS;
}

function tg_security_header_values() {
	$headers = array(
		'X-Content-Type-Options' => 'nosniff',
		'Referrer-Policy'        => 'strict-origin-when-cross-origin',
	);

	if ( is_ssl() ) {
		$headers['Strict-Transport-Security'] = 'max-age=' . tg_security_hsts_max_age();
	}

	return $headers;
}

function tg_security_send_headers( $frame_protection ) {
	if ( headers_sent() || wp_doing_cron() || ! tg_security_is_web_request() || ! tg_security_enabled( 'headers' ) ) {
		return;
	}

	$headers = tg_security_header_values();

	if ( $frame_protection ) {
		$headers['X-Frame-Options'] = 'SAMEORIGIN';
	}

	$sent = array();

	foreach ( headers_list() as $line ) {
		$sent[ strtolower( trim( strtok( $line, ':' ) ) ) ] = true;
	}

	foreach ( $headers as $name => $value ) {
		if ( empty( $sent[ strtolower( $name ) ] ) ) {
			header( $name . ': ' . $value );
		}
	}
}

/**
 * Frame protection is skipped for oEmbed views of posts, which other sites
 * are meant to put in an iframe, and on sites whose admin lives on another
 * host than the front end, where builder previews would be cross-origin.
 */
function tg_security_front_headers( $wp = null ) {
	$embed = is_object( $wp ) && ! empty( $wp->query_vars['embed'] );
	$hosts = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) === strtolower( (string) wp_parse_url( site_url(), PHP_URL_HOST ) );

	tg_security_send_headers( ! $embed && $hosts );
}

/**
 * wp-admin and wp-login.php already send X-Frame-Options themselves.
 */
function tg_security_admin_headers() {
	tg_security_send_headers( false );
}

function tg_security_rest_headers( $response ) {
	if ( ! ( $response instanceof WP_HTTP_Response ) || ! tg_security_enabled( 'headers' ) ) {
		return $response;
	}

	$existing = array_change_key_case( (array) $response->get_headers(), CASE_LOWER );

	foreach ( tg_security_header_values() as $name => $value ) {
		if ( ! isset( $existing[ strtolower( $name ) ] ) ) {
			$response->header( $name, $value );
		}
	}

	return $response;
}
