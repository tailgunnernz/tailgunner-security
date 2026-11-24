<?php
/**
 * Core update policy: maintenance and security releases install
 * automatically, major releases never do.
 *
 * The filters run last, so they win over wp-config constants
 * (AUTOMATIC_UPDATER_DISABLED, WP_AUTO_UPDATE_CORE), the "all new versions"
 * setting and update-blocking mu-plugins such as Installatron's. Core's own
 * locks still apply: no retry after a critical failure, or of the same
 * failed update. DISALLOW_FILE_MODS is respected. The health check reports
 * the settings it overrides.
 *
 * Where the site had background updates switched off, turning them back on
 * for core must not also start installing plugin and theme updates someone
 * once toggled on, so those stay off there (except this plugin's own).
 */

defined( 'ABSPATH' ) || exit;

/**
 * Remembers whether anything on the site tried to switch background updates
 * off, before this plugin overrode it.
 */
function tg_security_updater_was_disabled( $set = null ) {
	static $was_disabled = false;

	if ( null !== $set ) {
		$was_disabled = $was_disabled || (bool) $set;
	}

	return $was_disabled;
}

function tg_security_updater_disabled( $disabled ) {
	if ( ! tg_security_enabled( 'update_policy' ) ) {
		return $disabled;
	}

	tg_security_updater_was_disabled( $disabled );

	return false;
}

function tg_security_allow_dev_core( $allow ) {
	return tg_security_enabled( 'update_policy' ) ? false : $allow;
}

function tg_security_allow_minor_core( $allow ) {
	return tg_security_enabled( 'update_policy' ) ? true : $allow;
}

function tg_security_allow_major_core( $allow ) {
	return tg_security_enabled( 'update_policy' ) ? false : $allow;
}

/**
 * True when $new_version is a later release on the same major branch as the
 * running version, e.g. 7.1.5 to 7.1.6, not 7.1.5 to 7.2.
 */
function tg_security_is_minor_core_update( $new_version, $current_version = null ) {
	if ( null === $current_version ) {
		$current_version = get_bloginfo( 'version' );
	}

	$branch = function ( $version ) {
		return implode( '.', array_slice( preg_split( '/[.-]/', (string) $version ), 0, 2 ) );
	};

	return $branch( $new_version ) === $branch( $current_version )
		&& version_compare( $new_version, $current_version, '>' );
}

/**
 * Overrides any other auto_update_core filter (some block updates this way).
 * Core's check is asked again so its failure locks still hold; with this
 * plugin's allow_* filters it already comes out minor-only.
 */
function tg_security_auto_update_core( $update, $item ) {
	if ( ! tg_security_enabled( 'update_policy' ) || ! is_object( $item ) || empty( $item->current ) ) {
		return $update;
	}

	if ( ! tg_security_is_minor_core_update( $item->current ) ) {
		return false;
	}

	if ( class_exists( 'Core_Upgrader' ) ) {
		return (bool) Core_Upgrader::should_update_to_version( $item->current );
	}

	return true;
}

/**
 * On sites that had background updates off: no plugin or theme
 * auto-updates, apart from this plugin.
 */
function tg_security_frozen_plugin_updates( $update, $item ) {
	if ( ! tg_security_updater_was_disabled() || ! tg_security_enabled( 'update_policy' ) ) {
		return $update;
	}

	return isset( $item->plugin ) && tg_security_basename() === $item->plugin;
}

function tg_security_frozen_theme_updates( $update, $item = null ) {
	return tg_security_updater_was_disabled() && tg_security_enabled( 'update_policy' ) ? false : $update;
}

function tg_security_frozen_toggles( $enabled ) {
	return tg_security_updater_was_disabled() && tg_security_enabled( 'update_policy' ) ? false : $enabled;
}

/**
 * Settings on the site that disagree with the policy (this plugin overrides
 * them), for the health check.
 */
function tg_security_update_conflicts() {
	$conflicts = array();

	if ( defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED ) {
		$conflicts[] = 'AUTOMATIC_UPDATER_DISABLED';
	}

	if ( defined( 'WP_AUTO_UPDATE_CORE' ) && false === WP_AUTO_UPDATE_CORE ) {
		$conflicts[] = 'WP_AUTO_UPDATE_CORE=false';
	}

	if ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) {
		$conflicts[] = 'DISALLOW_FILE_MODS';
	}

	if ( 'enabled' === get_site_option( 'auto_update_core_major' ) ) {
		$conflicts[] = 'auto_update_core_major=enabled';
	}

	if ( file_exists( WPMU_PLUGIN_DIR . '/automation-by-installatron.php' ) ) {
		$conflicts[] = 'mu-plugins/automation-by-installatron.php';
	}

	$failed = get_site_option( 'auto_core_update_failed' );

	if ( is_array( $failed ) && ! empty( $failed['critical'] ) ) {
		$conflicts[] = 'core_update_failed_critical';
	}

	return $conflicts;
}
