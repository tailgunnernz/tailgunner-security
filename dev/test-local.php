<?php
// Pure-function tests that run without WordPress: php dev/test-local.php
// Covers the scanner patterns, the minor-update rule and health signature
// checks (with a throwaway key, never the monitor's).

define( 'ABSPATH', __DIR__ . '/' );
define( 'WPINC', 'wp-includes' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );

$GLOBALS['tg_test_options'] = array();
$GLOBALS['tg_test_filters'] = array();
$GLOBALS['tg_test_home']    = 'https://www.example.co.nz';

function apply_filters( $name, $value, ...$args ) {
	return isset( $GLOBALS['tg_test_filters'][ $name ] ) ? $GLOBALS['tg_test_filters'][ $name ]( $value, ...$args ) : $value;
}
function get_option( $name, $default = false ) {
	return array_key_exists( $name, $GLOBALS['tg_test_options'] ) ? $GLOBALS['tg_test_options'][ $name ] : $default;
}
function update_option( $name, $value, $autoload = null ) {
	$GLOBALS['tg_test_options'][ $name ] = $value;
	return true;
}
function home_url() { return $GLOBALS['tg_test_home']; }
function site_url() { return $GLOBALS['tg_test_home']; }
function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
function get_bloginfo( $what ) { return '7.1.5'; }

require dirname( __DIR__ ) . '/includes/common.php';
require dirname( __DIR__ ) . '/includes/scanner-block.php';
require dirname( __DIR__ ) . '/includes/update-policy.php';
require dirname( __DIR__ ) . '/includes/health.php';

$fails = 0;
function t( $label, $ok ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . "\n";
}

// Scanner block.
$blocked = array( '/.env', '/.env.local', '/.git/config', '/composer.json', '/phpinfo.php', '/phpinfo', '/vendor/autoload.php', '/backup.zip', '/db.sql', '/site.tar.gz', '/wp-content/backup.zip', '/_next/static/x.js', '/main.js', '/assets/js/app.js', '/config.yml', '/static/config.json', '/wp-config.php.bak', '/wp-config.bak', '/Dockerfile', '/actuator/health', '/telescope', '/.ENV', '/%2eenv', '//.env', '/app.js.map' );
$allowed = array( '/', '/about/', '/wp-content/uploads/2024/file.zip', '/wp-content/plugins/x/readme.txt', '/sitemap_index.xml', '/robots.txt', '/wp-json/wp/v2/posts', '/feed/', '/phpinfo-guide/', '/tg-probe-abc123', '/blog/my-post-about-env/', '/wp-admin/admin-ajax.php', '/shop/product.json-guide/', '/wp-content/themes/pro/js/app.js', '/vendors/', '/.well-known/acme-challenge/x', '/ads.txt', '/llms.txt' );

foreach ( $blocked as $path ) {
	t( "blocks $path", tg_security_scanner_blocked( tg_security_scanner_path( $path, '' ) ) );
}
foreach ( $allowed as $path ) {
	t( "allows $path", ! tg_security_scanner_blocked( tg_security_scanner_path( $path, '' ) ) );
}

t( 'query string ignored', ! tg_security_scanner_blocked( tg_security_scanner_path( '/?file=.env', '' ) ) );
t( 'subdirectory site blocks /blog/.env', tg_security_scanner_blocked( tg_security_scanner_path( '/blog/.env', '/blog' ) ) );
t( 'subdirectory site allows /blog/', ! tg_security_scanner_blocked( tg_security_scanner_path( '/blog/', '/blog/' ) ) );
t( 'subdirectory prefix only strips whole segment', '/blogger/.env' === tg_security_scanner_path( '/blogger/.env', '/blog' ) );

// Minor updates.
t( '7.1.5 -> 7.1.6 is minor', tg_security_is_minor_core_update( '7.1.6', '7.1.5' ) );
t( '7.1.5 -> 7.2 is not minor', ! tg_security_is_minor_core_update( '7.2', '7.1.5' ) );
t( '7.1.5 -> 7.1.5 is not an update', ! tg_security_is_minor_core_update( '7.1.5', '7.1.5' ) );
t( '7.1 -> 7.1.1 is minor', tg_security_is_minor_core_update( '7.1.1', '7.1' ) );
t( '7.1.5 -> 8.0 is not minor', ! tg_security_is_minor_core_update( '8.0', '7.1.5' ) );
t( '7.2-RC1 -> 7.2 is minor (same branch)', tg_security_is_minor_core_update( '7.2', '7.2-RC1' ) );

// Health signatures.
$kp = sodium_crypto_sign_keypair();
$sk = sodium_crypto_sign_secretkey( $kp );
$GLOBALS['tg_test_filters']['tg_security_health_keys'] = function ( $keys ) use ( $kp ) {
	return array( base64_encode( sodium_crypto_sign_publickey( $kp ) ) );
};
$sign = function ( $body ) use ( $sk ) {
	return base64_encode( sodium_crypto_sign_detached( $body, $sk ) );
};

$now  = 1764000000000;
$body = json_encode( array( 'host' => 'example.co.nz', 'ts' => $now ) );
t( 'valid request accepted', true === tg_security_health_verify( $body, $sign( $body ), $now ) );
t( 'same request again is a replay', 'replay' === tg_security_health_verify( $body, $sign( $body ), $now ) );

$body2 = json_encode( array( 'host' => 'www.example.co.nz', 'ts' => $now + 1000 ) );
t( 'www host accepted', true === tg_security_health_verify( $body2, $sign( $body2 ), $now + 1000 ) );

$body3 = json_encode( array( 'host' => 'other.co.nz', 'ts' => $now + 2000 ) );
t( 'other host refused', 'host' === tg_security_health_verify( $body3, $sign( $body3 ), $now + 2000 ) );

$body4 = json_encode( array( 'host' => 'example.co.nz', 'ts' => $now + 3000 ) );
t( 'tampered body refused', 'signature' === tg_security_health_verify( str_replace( '3000', '3001', $body4 ), $sign( $body4 ), $now + 3000 ) );
t( 'old timestamp refused', 'clock' === tg_security_health_verify( $body4, $sign( $body4 ), $now + 3000 + 301000 ) );
t( 'missing signature refused', 'signature' === tg_security_health_verify( $body4, '', $now + 3000 ) );
t( 'garbage signature refused', 'signature' === tg_security_health_verify( $body4, 'not base64!!', $now + 3000 ) );
t( 'empty body refused', 'body' === tg_security_health_verify( '', $sign( '' ), $now ) );

$body5 = json_encode( array( 'host' => 'example.co.nz', 'ts' => (string) ( $now + 4000 ) ) );
t( 'string timestamp refused', 'payload' === tg_security_health_verify( $body5, $sign( $body5 ), $now + 4000 ) );

$other = sodium_crypto_sign_keypair();
$body6 = json_encode( array( 'host' => 'example.co.nz', 'ts' => $now + 5000 ) );
t( 'signature from another key refused', 'signature' === tg_security_health_verify( $body6, base64_encode( sodium_crypto_sign_detached( $body6, sodium_crypto_sign_secretkey( $other ) ) ), $now + 5000 ) );
t( 'valid newer request accepted', true === tg_security_health_verify( $body6, $sign( $body6 ), $now + 5000 ) );

echo $fails ? "\n$fails FAILED\n" : "\nall passed\n";
exit( $fails ? 1 : 0 );
