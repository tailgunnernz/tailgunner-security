<?php
/**
 * The mu-plugin loader.
 *
 * A normal plugin loads too late to repair active_plugins, and GitHub updates
 * can't reach an mu-plugin. So the plugin writes a short loader to
 * wp-content/mu-plugins/0-tailgunner-security.php that includes early.php
 * from the plugin folder. Updates to the plugin are picked up straight away.
 *
 * Deactivating the plugin removes the loader, even from recovery mode or
 * `wp plugin deactivate --skip-plugins`, because the loader registers that
 * cleanup itself. A tombstone file stops a request that is still running
 * during deactivation from writing the loader back. Deleting the plugin
 * folder over SFTP leaves an inert loader behind, which does nothing.
 *
 * The loader catches errors thrown while early.php loads, so a broken release
 * leaves the site up with the plugin off (and the health check silent)
 * instead of taking down every request, wp-cron and WP-CLI with it.
 */

defined( 'ABSPATH' ) || exit;

define( 'TG_SECURITY_LOADER_VERSION', '2' );

function tg_security_loader_path() {
	return WPMU_PLUGIN_DIR . '/0-tailgunner-security.php';
}

function tg_security_loader_tombstone() {
	return tg_security_loader_path() . '.off';
}

function tg_security_loader_id() {
	return TG_SECURITY_LOADER_VERSION . ':' . basename( dirname( TG_SECURITY_FILE ) );
}

function tg_security_loader_code() {
	$folder = basename( dirname( TG_SECURITY_FILE ) );
	$early  = var_export( '/' . $folder . '/early.php', true );
	$hook   = var_export( 'deactivate_' . $folder . '/' . basename( TG_SECURITY_FILE ), true );
	$id     = var_export( tg_security_loader_id(), true );

	return <<<PHP
<?php
/**
 * Plugin Name: Tailgunner Security loader
 * Description: Starts the Tailgunner Security plugin before other plugins load. The plugin writes this file and removes it when deactivated. To switch everything off in an emergency, delete the tailgunner-security plugin folder.
 */

defined( 'ABSPATH' ) || exit;

define( 'TG_SECURITY_LOADER', {$id} );

add_action(
	{$hook},
	function () {
		@touch( __FILE__ . '.off' );
		@unlink( __FILE__ );
	}
);

if ( is_readable( WP_PLUGIN_DIR . {$early} ) ) {
	try {
		include_once WP_PLUGIN_DIR . {$early};
	} catch ( Throwable \$e ) {
		error_log( 'tailgunner-security: not loaded: ' . \$e->getMessage() );
	}
}

PHP;
}

function tg_security_loader_current() {
	return defined( 'TG_SECURITY_LOADER' ) && TG_SECURITY_LOADER === tg_security_loader_id();
}

function tg_security_maybe_install_loader() {
	if ( tg_security_loader_current() || get_transient( 'tg_security_loader_failed' ) || file_exists( tg_security_loader_tombstone() ) ) {
		return;
	}

	tg_security_install_loader();
}

function tg_security_activate() {
	if ( file_exists( tg_security_loader_tombstone() ) ) {
		@unlink( tg_security_loader_tombstone() );
	}

	delete_transient( 'tg_security_loader_failed' );
	tg_security_install_loader();
}

function tg_security_install_loader() {
	$path = tg_security_loader_path();
	$code = tg_security_loader_code();

	if ( is_readable( $path ) && file_get_contents( $path ) === $code ) {
		return true;
	}

	$tmp = $path . '.' . wp_generate_password( 8, false ) . '.tmp';

	// Written to a temporary name and renamed, so a request never includes
	// half a file.
	if ( ! wp_mkdir_p( WPMU_PLUGIN_DIR ) || false === @file_put_contents( $tmp, $code ) || ! @rename( $tmp, $path ) ) {
		if ( file_exists( $tmp ) ) {
			@unlink( $tmp );
		}

		set_transient( 'tg_security_loader_failed', 1, HOUR_IN_SECONDS );
		tg_security_record( 'loader_failed', array( 'path' => $path ) );

		return false;
	}

	delete_transient( 'tg_security_loader_failed' );

	return true;
}

function tg_security_remove_loader() {
	$path = tg_security_loader_path();

	@touch( tg_security_loader_tombstone() );

	if ( ! is_file( $path ) || false === strpos( (string) file_get_contents( $path ), 'TG_SECURITY_LOADER' ) ) {
		return;
	}

	if ( @unlink( $path ) || ! file_exists( $path ) ) {
		return;
	}

	// Typically wp-cli running as a different user than PHP. The plugin keeps
	// running until the file goes, so say so loudly.
	$message = "Tailgunner Security is still running: delete {$path} by hand.";

	error_log( 'tailgunner-security: ' . $message );
	tg_security_record( 'loader_failed', array( 'path' => $path, 'action' => 'remove' ) );

	if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( 'WP_CLI' ) ) {
		WP_CLI::warning( $message );
	}
}
