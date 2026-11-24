<?php
/**
 * ACF cache guard.
 *
 * ACF caches the list of its field groups, post types, taxonomies and options
 * pages in the object cache. If the database drops out while that list is
 * built, the cache holds an empty list, and with a persistent object cache it
 * stays that way: one of our sites lost two custom post types (and every URL
 * under them) twice this way.
 *
 * Before ACF registers anything on init, the guard looks for an empty cached
 * list and checks the database. If ACF posts of that type exist, it deletes
 * the cached list so ACF rebuilds it. A list confirmed empty is not checked
 * again for ten minutes.
 */

defined( 'ABSPATH' ) || exit;

function tg_security_acf_guard_types() {
	return array(
		'acf_get_field_group_posts'     => 'acf-field-group',
		'acf_get_post_type_posts'       => 'acf-post-type',
		'acf_get_taxonomy_posts'        => 'acf-taxonomy',
		'acf_get_ui_options_page_posts' => 'acf-ui-options-page',
	);
}

function tg_security_acf_guard() {
	global $wpdb;

	if ( ! wp_using_ext_object_cache() || ! function_exists( 'acf_get_internal_post_type_posts' ) || ! tg_security_enabled( 'acf_guard' ) ) {
		return;
	}

	foreach ( tg_security_acf_guard_types() as $key => $post_type ) {
		$cache_key = function_exists( 'acf_cache_key' ) ? acf_cache_key( $key ) : $key;

		if ( array() !== wp_cache_get( $cache_key, 'acf' ) ) {
			continue;
		}

		$marker = 'acf_empty_' . md5( $cache_key );

		if ( wp_cache_get( $marker, 'tg_security' ) ) {
			continue;
		}

		$suppress = $wpdb->suppress_errors();
		$found    = $wpdb->get_var( $wpdb->prepare( "SELECT ID FROM $wpdb->posts WHERE post_type = %s AND post_status IN ('publish','acf-disabled') LIMIT 1", $post_type ) );
		$failed   = ! $wpdb->ready || '' !== $wpdb->last_error;
		$wpdb->suppress_errors( $suppress );

		if ( $failed ) {
			continue;
		}

		if ( null === $found ) {
			wp_cache_set( $marker, 1, 'tg_security', 10 * MINUTE_IN_SECONDS );
			continue;
		}

		wp_cache_delete( $cache_key, 'acf' );

		error_log( "tailgunner-security: ACF cache '{$key}' was empty but {$post_type} posts exist; cache cleared" );
		tg_security_record( 'acf_heal', array( 'cache' => $key ) );
	}
}
