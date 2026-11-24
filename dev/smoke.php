<?php
// Loads early.php against stub hook functions and checks every hooked
// callback exists. Catches a fatal at include time (which would take down
// every site, since the loader runs as an mu-plugin) and hooks pointing at
// functions that were renamed or never written.
//
//   php dev/smoke.php [path/to/early.php]

define( 'ABSPATH', __DIR__ . '/' );
define( 'WPINC', 'wp-includes' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );

$GLOBALS['wpdb']       = (object) array( 'prefix' => 'wp_' );
$GLOBALS['smoke_hooks'] = array();

function add_filter( $hook, $callback, $priority = 10, $args = 1 ) {
	$GLOBALS['smoke_hooks'][] = array( $hook, $callback );
	return true;
}
function add_action( $hook, $callback, $priority = 10, $args = 1 ) {
	return add_filter( $hook, $callback, $priority, $args );
}
function did_action( $hook ) { return 0; }
function apply_filters( $hook, $value ) { return $value; }

$early = isset( $argv[1] ) ? $argv[1] : dirname( __DIR__ ) . '/early.php';
require $early;

$fails = 0;

foreach ( $GLOBALS['smoke_hooks'] as $hook ) {
	list( $name, $callback ) = $hook;

	if ( is_string( $callback ) && ! function_exists( $callback ) ) {
		echo "FAIL $name -> $callback is not defined\n";
		++$fails;
	}
}

if ( ! defined( 'TG_SECURITY_VERSION' ) ) {
	echo "FAIL TG_SECURITY_VERSION not defined\n";
	++$fails;
}

printf( "%d hooks checked on PHP %s\n", count( $GLOBALS['smoke_hooks'] ), PHP_VERSION );
exit( $fails ? 1 : 0 );
