<?php
/**
 * Basic hardening:
 * - XML-RPC off (left alone when Jetpack is connected, as it needs it);
 * - the theme and plugin file editor off;
 * - logged-out visitors can't list usernames through ?author=N, the users
 *   REST endpoint or the users sitemap;
 * - the default role for new registrations can't be one that manages the
 *   site or other people's content;
 * - no WordPress version in the generator tag.
 */

defined( 'ABSPATH' ) || exit;

function tg_security_xmlrpc_blocked() {
	return tg_security_enabled( 'xmlrpc' ) && ! tg_security_jetpack_needs_xmlrpc();
}

/**
 * The Jetpack plugin needs XML-RPC, including to connect in the first place.
 * WooCommerce and others bundle Jetpack's connection library, so for them
 * only a live connection (WooPayments, say) counts.
 */
function tg_security_jetpack_needs_xmlrpc() {
	static $needs = null;

	if ( null !== $needs ) {
		return $needs;
	}

	if ( class_exists( 'Jetpack', false ) ) {
		return $needs = true;
	}

	// Too early to tell: plugins haven't loaded. Don't cache that answer.
	if ( ! did_action( 'plugins_loaded' ) ) {
		return false;
	}

	$needs = false;

	if ( class_exists( 'Automattic\Jetpack\Connection\Manager' ) ) {
		try {
			$manager = new \Automattic\Jetpack\Connection\Manager();

			if ( method_exists( $manager, 'is_connected' ) ) {
				$needs = (bool) $manager->is_connected();
			} elseif ( method_exists( $manager, 'is_active' ) ) {
				$needs = (bool) $manager->is_active();
			}
		} catch ( Throwable $e ) {
			$needs = true;
		}
	}

	return $needs;
}

/**
 * Runs once every plugin has loaded, so Jetpack can be detected and plugins
 * can use the feature filter.
 */
function tg_security_hardening_early() {
	if ( ! defined( 'DISALLOW_FILE_EDIT' ) && tg_security_enabled( 'file_editor' ) ) {
		define( 'DISALLOW_FILE_EDIT', true );
	}

	if ( ! tg_security_xmlrpc_blocked() ) {
		return;
	}

	remove_action( 'wp_head', 'rsd_link' );

	if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
		status_header( 403 );
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo 'XML-RPC is turned off on this site.';
		exit;
	}
}

function tg_security_remove_pingback_header( $headers ) {
	if ( is_array( $headers ) && tg_security_xmlrpc_blocked() ) {
		unset( $headers['X-Pingback'] );
	}

	return $headers;
}

/**
 * /?author=1 redirects to /author/<username>/, which hands out logins one ID
 * at a time. Logged-out visitors get a 404 instead. Sites on plain
 * permalinks are left alone, as that is their only author archive URL.
 */
function tg_security_block_author_scan() {
	if ( ! isset( $_GET['author'] ) || is_user_logged_in() || ! get_option( 'permalink_structure' ) || ! tg_security_enabled( 'user_enumeration' ) ) {
		return;
	}

	if ( ! is_author() && ! is_404() ) {
		return;
	}

	global $wp_query;

	$wp_query->set_404();
	status_header( 404 );
	nocache_headers();
	remove_action( 'template_redirect', 'redirect_canonical' );
}

function tg_security_block_rest_users( $result, $server, $request ) {
	if ( null !== $result || is_user_logged_in() || ! tg_security_enabled( 'user_enumeration' ) ) {
		return $result;
	}

	if ( preg_match( '#^/wp/v2/users(/|$)#i', (string) $request->get_route() ) ) {
		return new WP_Error( 'rest_user_cannot_view', 'Sorry, you are not allowed to list users.', array( 'status' => rest_authorization_required_code() ) );
	}

	return $result;
}

function tg_security_no_user_sitemap( $provider, $name ) {
	if ( 'users' === $name && tg_security_enabled( 'user_enumeration' ) ) {
		return false;
	}

	return $provider;
}

/**
 * A role that can manage options, users or other people's posts is never
 * handed to strangers who register: they get Subscriber instead.
 */
function tg_security_safe_default_role( $role ) {
	if ( ! tg_security_enabled( 'default_role' ) || ! function_exists( 'get_role' ) ) {
		return $role;
	}

	$object = get_role( $role );

	if ( ! $object ) {
		return $role;
	}

	foreach ( array( 'manage_options', 'edit_users', 'promote_users', 'edit_others_posts' ) as $cap ) {
		if ( $object->has_cap( $cap ) ) {
			return 'subscriber';
		}
	}

	return $role;
}

function tg_security_hide_generator( $generator ) {
	return tg_security_enabled( 'hide_version' ) ? '' : $generator;
}
