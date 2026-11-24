<?php
// Reads the raw object cache (no get_option, so this can't heal anything):
//   wp eval-file poison-check.php
$c   = wp_cache_get( 'notoptions', 'options', true );
$bad = array();
foreach ( array( 'template', 'stylesheet', 'home', 'siteurl', 'blog_charset', 'active_plugins' ) as $o ) {
	if ( is_array( $c ) && isset( $c[ $o ] ) ) {
		$bad[] = $o;
	}
}
echo 'notoptions poisoned: ', $bad ? implode( ',', $bad ) : 'none', "\n";
