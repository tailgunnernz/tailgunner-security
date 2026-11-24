<?php
// Marks core options as missing in the object cache, as a database outage can:
//   wp eval-file poison.php
// The options are removed from alloptions and marked missing in notoptions,
// after every shutdown hook so this CLI process can't heal them itself.
// The next uncached web request should heal them (check with poison-check.php).
// Fallback if it doesn't: wp cache flush.

register_shutdown_function(
	function () {
		$names = array( 'template', 'stylesheet', 'home', 'siteurl', 'blog_charset', 'active_plugins' );
		$all   = wp_load_alloptions();
		foreach ( $names as $o ) {
			unset( $all[ $o ] );
		}
		wp_cache_set( 'alloptions', $all, 'options' );
		$n = wp_cache_get( 'notoptions', 'options', true );
		$n = is_array( $n ) ? $n : array();
		foreach ( $names as $o ) {
			$n[ $o ] = true;
			wp_cache_delete( $o, 'options' );
		}
		wp_cache_set( 'notoptions', $n, 'options' );
		$c = wp_cache_get( 'notoptions', 'options', true );
		echo 'poisoned: ', implode( ',', array_intersect( $names, array_keys( (array) $c ) ) ), "\n";
	}
);
