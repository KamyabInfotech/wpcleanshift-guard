<?php
/**
 * CleanShift Guard — Security Stack Detector
 *
 * PHP equivalent of the Python SecurityStack class in extended_scanners.py.
 * Auto-detects Wordfence, Sucuri, iThemes Security, CSF, Fail2ban,
 * Imunify360, and Cloudflare so overlapping guards can defer gracefully.
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Detects installed security tools and generates a guard enable/disable map.
 *
 * @since 1.0.0
 */
class CleanShift_Security_Stack {

	/** @var bool Wordfence detected. */
	private $wordfence = false;

	/** @var bool Sucuri Scanner detected. */
	private $sucuri = false;

	/** @var bool iThemes Security (Solid Security) detected. */
	private $ithemes = false;

	/** @var bool ConfigServer Firewall detected. */
	private $csf = false;

	/** @var bool Fail2ban detected. */
	private $fail2ban = false;

	/** @var bool Imunify360 detected. */
	private $imunify360 = false;

	/** @var bool Cloudflare detected (via header). */
	private $cloudflare = false;

	/** @var bool All-In-One WP Security detected. */
	private $aio_security = false;

	/**
	 * Magic getter for backward-compatible read access to detection flags.
	 *
	 * @param string $name Property name.
	 * @return bool|null The property value or null if it does not exist.
	 */
	public function __get( $name ) {
		$allowed = array( 'wordfence', 'sucuri', 'ithemes', 'csf', 'fail2ban', 'imunify360', 'cloudflare', 'aio_security' );
		if ( in_array( $name, $allowed, true ) ) {
			return $this->$name;
		}
		return null;
	}

	/**
	 * Magic isset for backward-compatible property checks.
	 *
	 * @param string $name Property name.
	 * @return bool
	 */
	public function __isset( $name ) {
		$allowed = array( 'wordfence', 'sucuri', 'ithemes', 'csf', 'fail2ban', 'imunify360', 'cloudflare', 'aio_security' );
		return in_array( $name, $allowed, true );
	}

	/**
	 * Run detection probes for every supported security tool.
	 *
	 * @return void
	 */
	public function detect() {
		try {
			// WordPress security plugins (constant-based detection).
			$this->wordfence    = defined( 'WORDFENCE_VERSION' );
			$this->sucuri       = defined( 'SUCURISCAN_VERSION' ) || defined( 'SUCURISCAN' );
			$this->ithemes      = defined( 'ITSEC_CORE_DIR' ) || defined( 'ITSEC_PLUGIN_FILE' );
			$this->aio_security = defined( 'AIO_WP_SECURITY_VERSION' );

			// Server-level tools (file-existence probes).
			$this->csf        = @file_exists( '/etc/csf/csf.conf' );
			$this->fail2ban   = @file_exists( '/etc/fail2ban' ) || @file_exists( '/etc/fail2ban/jail.conf' );
			$this->imunify360 = @file_exists( '/etc/sysconfig/imunify360' ) || @file_exists( '/usr/bin/imunify360-agent' );

			// Cloudflare — check connecting-IP header.
			$this->cloudflare = ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] );

		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Stack] detect() error: ' . $e->getMessage() );
			}
		}
	}

	/**
	 * Build the guard enable/disable map based on detected stack.
	 *
	 * Guards that overlap with another tool's coverage are disabled to
	 * avoid duplicated blocks and double-logging.
	 *
	 * @return array<string, bool>
	 */
	public function get_guard_config() {
		return array(
			// Wordfence covers upload scanning with its own firewall.
			'upload'  => ! $this->wordfence,

			// Wordfence / Fail2ban / Imunify360 handle brute-force.
			'login'   => ! $this->wordfence && ! $this->fail2ban && ! $this->imunify360,

			// Nobody else monitors rogue admin creation.
			'user'    => true,

			// Nobody else monitors wp_options writes.
			'option'  => true,

			// Nobody else audits cron registration.
			'cron'    => true,

			// Wordfence / iThemes cover REST & XML-RPC hardening.
			'api'     => ! $this->wordfence && ! $this->ithemes,

			// Wordfence / iThemes can disable the file editor.
			'editor'  => ! $this->wordfence && ! $this->ithemes,

			// Wordfence / Sucuri / Imunify360 already do request-level WAF filtering.
			'request' => ! $this->wordfence && ! $this->sucuri && ! $this->imunify360,

			// Payload inspection: defer if Wordfence/Sucuri/Imunify360 already inspect payloads.
			'payload' => ! $this->wordfence && ! $this->sucuri && ! $this->imunify360,

			// Virtual patching: always enabled — our CVE-specific patches complement
			// other security tools rather than duplicating them.
			'vpatch'  => true,
		);
	}

	/**
	 * True if no external security systems are detected.
	 *
	 * @return bool
	 */
	public function is_standalone() {
		return ! $this->wordfence
			&& ! $this->sucuri
			&& ! $this->ithemes
			&& ! $this->csf
			&& ! $this->fail2ban
			&& ! $this->imunify360
			&& ! $this->cloudflare
			&& ! $this->aio_security;
	}

	/**
	 * Return a human-readable summary of detected tools.
	 *
	 * @return string
	 */
	public function summary_text() {
		if ( $this->is_standalone() ) {
			return 'No external security tools detected (standalone server).';
		}

		$parts = array();
		if ( $this->wordfence )    { $parts[] = 'Wordfence'; }
		if ( $this->sucuri )       { $parts[] = 'Sucuri'; }
		if ( $this->ithemes )      { $parts[] = 'iThemes Security'; }
		if ( $this->aio_security ) { $parts[] = 'All-In-One WP Security'; }
		if ( $this->csf )          { $parts[] = 'CSF'; }
		if ( $this->fail2ban )     { $parts[] = 'Fail2ban'; }
		if ( $this->imunify360 )   { $parts[] = 'Imunify360'; }
		if ( $this->cloudflare )   { $parts[] = 'Cloudflare'; }

		return 'Active security: ' . implode( ', ', $parts );
	}

	/**
	 * Get a structured list of all detected tools with their category.
	 *
	 * @return array<int, array{name: string, category: string}>
	 */
	public function get_detected_list() {
		$list = array();

		$tools = array(
			array( 'prop' => 'wordfence',    'name' => 'Wordfence',             'category' => 'WordPress Plugin' ),
			array( 'prop' => 'sucuri',       'name' => 'Sucuri Scanner',        'category' => 'WordPress Plugin' ),
			array( 'prop' => 'ithemes',      'name' => 'iThemes Security',      'category' => 'WordPress Plugin' ),
			array( 'prop' => 'aio_security', 'name' => 'All-In-One WP Security','category' => 'WordPress Plugin' ),
			array( 'prop' => 'csf',          'name' => 'ConfigServer Firewall', 'category' => 'Server-Level' ),
			array( 'prop' => 'fail2ban',     'name' => 'Fail2ban',              'category' => 'Server-Level' ),
			array( 'prop' => 'imunify360',   'name' => 'Imunify360',            'category' => 'Server-Level' ),
			array( 'prop' => 'cloudflare',   'name' => 'Cloudflare',            'category' => 'CDN / WAF' ),
		);

		foreach ( $tools as $tool ) {
			if ( $this->{$tool['prop']} ) {
				$list[] = array(
					'name'     => $tool['name'],
					'category' => $tool['category'],
				);
			}
		}

		return $list;
	}
}
