<?php
/**
 * Mail failure log.
 *
 * Records every send WordPress reports as failed (refused SMTP login,
 * unreachable relay, API error, bad address). The health check reports the
 * count and the latest errors, and the monitor alerts from there, so a broken
 * mailer on the site can't swallow its own alert.
 *
 * It can't see mail a server accepts and then bounces or files as spam.
 */

defined( 'ABSPATH' ) || exit;

function tg_security_mail_failed( $error ) {
	if ( ! tg_security_enabled( 'mail_log' ) ) {
		return;
	}

	$data = is_wp_error( $error ) ? $error->get_error_data() : array();
	$data = is_array( $data ) ? $data : array();
	$to   = isset( $data['to'] ) ? $data['to'] : array();

	if ( is_string( $to ) ) {
		$to = explode( ',', $to );
	}

	tg_security_record(
		'mail_failed',
		array(
			'error'   => tg_security_redact( tg_security_clip( is_wp_error( $error ) ? $error->get_error_message() : 'unknown error', 300 ) ),
			'to'      => count( array_filter( (array) $to ) ),
			'subject' => isset( $data['subject'] ) ? tg_security_redact( tg_security_clip( $data['subject'], 80 ) ) : '',
		)
	);
}

/**
 * Keeps the domain of any email address in the text and hides the rest, so
 * the log shows which mail server refused without collecting addresses.
 */
function tg_security_redact( $text ) {
	return preg_replace( '/[^\s<>"\'(),;:]+@([a-z0-9.-]+\.[a-z]{2,})/i', '***@$1', (string) $text );
}
