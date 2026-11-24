<?php
/**
 * Scanner block.
 *
 * Bots probe every site for leaked config, backups and other frameworks'
 * files. On Cloudways Hybrid apps the TG scanner block in .htaccess turns
 * them away; these are the same rules in PHP, for sites without it (nginx,
 * Lightning, other hosts). A probe that reaches PHP is answered with a short
 * 403 before WordPress loads plugins or the theme.
 *
 * Only requests that got as far as WordPress are checked, so real files on
 * disk are never affected.
 */

defined( 'ABSPATH' ) || exit;

/**
 * Matched against the request path relative to the site's home, with a
 * leading slash. Keep in step with ~/tg-scanner-block.txt on the servers.
 */
function tg_security_scanner_patterns() {
	return array(
		'#^/(\.env|\.git|\.svn|\.hg|composer\.(json|lock)|package\.json|yarn\.lock|settings\.json|config\.yml|bitbucket-pipelines\.yml|runtime-config\.js|sendgrid\.env|phpinfo(\.php)?$|_profiler|vendor/|wp-content/plugins/hellopress/)#i',
		'#^/(?!wp-content/(uploads|plugins|themes)/).*\.(sql|sql\.gz|bak|old|orig|swp|tar|tar\.gz|tgz|zip|rar|7z)$#i',
		'#^/(_next|_nuxt|_astro|_app)/#i',
		'#^/((static|assets|public|js|build|config|static/js|assets/js|assets/environments)/)?[^/]+\.(js|json|map|ya?ml|tfstate|tfvars|backup)$#i',
		'#^/(jenkinsfile|kubeconfig|wp-config\.(txt|bak|old|orig|save))$#i',
		'#^/(actuator|telescope|_ignition|v2/_catalog|elmah\.axd|app/etc/local\.xml|config/master\.key|dockerfile|web\.config|env\.txt|config\.env)(/|$)#i',
	);
}

/**
 * The decoded request path relative to the site's home path.
 */
function tg_security_scanner_path( $request_uri, $home_path ) {
	$parts = explode( '?', (string) $request_uri, 2 );
	$path  = '/' . ltrim( rawurldecode( $parts[0] ), '/' );
	$path  = preg_replace( '#/{2,}#', '/', $path );

	$home_path = '/' . trim( (string) $home_path, '/' );

	if ( '/' !== $home_path ) {
		if ( 0 === stripos( $path . '/', $home_path . '/' ) ) {
			$path = '/' . ltrim( (string) substr( $path, strlen( $home_path ) ), '/' );
		}
	}

	return $path;
}

function tg_security_scanner_blocked( $path ) {
	foreach ( tg_security_scanner_patterns() as $pattern ) {
		if ( preg_match( $pattern, $path ) ) {
			return true;
		}
	}

	return false;
}

function tg_security_scanner_check() {
	if ( ! tg_security_is_web_request() || empty( $_SERVER['REQUEST_URI'] ) || ! tg_security_enabled( 'scanner_block' ) ) {
		return;
	}

	$home_path = wp_parse_url( (string) get_option( 'home' ), PHP_URL_PATH );
	$path      = tg_security_scanner_path( $_SERVER['REQUEST_URI'], $home_path );

	if ( ! tg_security_scanner_blocked( $path ) ) {
		return;
	}

	status_header( 403 );
	header( 'Content-Type: text/plain; charset=utf-8' );
	header( 'X-Robots-Tag: noindex' );
	echo 'Forbidden';
	exit;
}
