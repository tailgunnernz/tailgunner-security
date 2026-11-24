<?php
/**
 * Updates come from GitHub releases. The repo is public, so no token is
 * needed. Only the zip the release workflow attaches is accepted, never the
 * source zipball, so a failed build serves nothing rather than a broken plugin.
 */

defined( 'ABSPATH' ) || exit;

require_once TG_SECURITY_DIR . 'vendor/plugin-update-checker/plugin-update-checker.php';

$tg_security_update_checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
	'https://github.com/tailgunnernz/tailgunner-security/',
	TG_SECURITY_FILE,
	'tailgunner-security'
);

$tg_security_update_api = $tg_security_update_checker->getVcsApi();
$tg_security_update_api->enableReleaseAssets( '/^tailgunner-security\.zip$/', $tg_security_update_api::REQUIRE_RELEASE_ASSETS );

// Without this, a release with no zip (still building, or the build failed)
// or a GitHub API error makes the checker fall back to the newest tag's
// source zipball, which would ship unbuilt or rejected code to every site.
add_filter(
	$tg_security_update_checker->getUniqueName( 'vcs_update_detection_strategies' ),
	function ( $strategies ) {
		return array_intersect_key( (array) $strategies, array( 'latest_release' => true ) );
	}
);

// Every release installs itself on the next WordPress cron run.
add_filter(
	'auto_update_plugin',
	function ( $update, $item ) {
		if ( isset( $item->plugin ) && plugin_basename( TG_SECURITY_FILE ) === $item->plugin ) {
			return true;
		}

		return $update;
	},
	10,
	2
);
