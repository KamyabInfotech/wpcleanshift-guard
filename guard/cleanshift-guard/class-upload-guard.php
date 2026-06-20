<?php
/**
 * CleanShift Guard — Upload Guard
 *
 * Hooks into wp_handle_upload_prefilter to inspect every file upload
 * before it reaches the filesystem. Blocks PHP disguised as images,
 * double-extension tricks, oversized .ico webshells, and SVG XSS.
 *
 * Defers to Wordfence if present (Wordfence scans uploads with its
 * own firewall rules).
 *
 * @package CleanShift_Guard
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Real-time upload inspection guard.
 *
 * @since 1.0.0
 */
class CleanShift_Upload_Guard {

	/**
	 * PHP-related extensions that should never be uploaded.
	 *
	 * @var array<int, string>
	 */
	private $dangerous_extensions = array(
		'php', 'php3', 'php4', 'php5', 'php7', 'php8',
		'phtml', 'phar', 'phps', 'pht', 'pgif', 'shtml',
		'cgi', 'pl', 'py', 'jsp', 'asp', 'aspx',
		'exe', 'sh', 'bat', 'cmd',
	);

	/**
	 * Maximum allowed size for .ico files (bytes). Anything larger is
	 * almost certainly a disguised webshell.
	 *
	 * @var int
	 */
	private $ico_max_size = 524288; // 500 KB

	/**
	 * Register the upload prefilter hook.
	 *
	 * @return void
	 */
	public function init() {
		if ( ! CleanShift_Guard::instance()->guard_enabled( 'upload' ) ) {
			return;
		}
		add_filter( 'wp_handle_upload_prefilter', array( $this, 'inspect_upload' ), 99 );
	}

	/**
	 * Inspect an upload before it is moved to the final destination.
	 *
	 * Runs as a wp_handle_upload_prefilter callback. The $file array
	 * has keys: name, type, tmp_name, error, size.
	 *
	 * Returning an array with an 'error' key aborts the upload.
	 *
	 * @param array $file Upload data array.
	 * @return array Possibly modified upload data (with 'error' set on block).
	 */
	public function inspect_upload( $file ) {
		try {
			$guard    = CleanShift_Guard::instance();
			$filename = isset( $file['name'] ) ? $file['name'] : '';
			$tmp_path = isset( $file['tmp_name'] ) ? $file['tmp_name'] : '';
			$size     = isset( $file['size'] ) ? (int) $file['size'] : 0;
			$user_id  = get_current_user_id();

			// --- Check 1: Dangerous extension (including double extensions) ---
			$block_reason = $this->check_extension( $filename );
			if ( $block_reason ) {
				return $this->block_upload( $file, $block_reason, 'dangerous_extension', 'critical', $user_id );
			}

			// --- Check 2: Double extension trick (file.php.jpg) ---
			$block_reason = $this->check_double_extension( $filename );
			if ( $block_reason ) {
				return $this->block_upload( $file, $block_reason, 'double_extension', 'critical', $user_id );
			}

			// --- Check 3: Oversized .ico file ---
			$block_reason = $this->check_ico_size( $filename, $size );
			if ( $block_reason ) {
				return $this->block_upload( $file, $block_reason, 'oversized_ico', 'high', $user_id );
			}

			// --- Check 4: PHP tags in file content (first 8 KB) ---
			$block_reason = $this->check_php_content( $tmp_path, $filename );
			if ( $block_reason ) {
				return $this->block_upload( $file, $block_reason, 'php_in_content', 'critical', $user_id );
			}

			// --- Check 5: SVG with script / event handlers ---
			$block_reason = $this->check_svg_xss( $tmp_path, $filename );
			if ( $block_reason ) {
				return $this->block_upload( $file, $block_reason, 'svg_xss', 'high', $user_id );
			}

			// All checks passed — log as allowed.
			$guard->audit_log->log(
				'upload',
				'upload_file',
				'ALLOWED',
				'info',
				array(
					'filename' => $filename,
					'size'     => $size,
				),
				$user_id
			);

			return $file;

		} catch ( \Throwable $e ) {
			// Never crash uploads.
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( '[CleanShift Upload] inspect error: ' . $e->getMessage() );
			}
			return $file;
		}
	}

	/**
	 * Check for dangerous file extensions.
	 *
	 * @param string $filename Original filename.
	 * @return string Empty string if safe, block reason otherwise.
	 */
	private function check_extension( $filename ) {
		$ext = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
		if ( in_array( $ext, $this->dangerous_extensions, true ) ) {
			return sprintf(
				'File extension ".%s" is not allowed. This file type can execute code on the server.',
				$ext
			);
		}
		return '';
	}

	/**
	 * Check for double-extension attacks (e.g. file.php.jpg).
	 *
	 * @param string $filename Original filename.
	 * @return string Block reason or empty string.
	 */
	private function check_double_extension( $filename ) {
		$name_lower = strtolower( $filename );
		foreach ( $this->dangerous_extensions as $ext ) {
			if ( false !== strpos( $name_lower, '.' . $ext . '.' ) ) {
				return sprintf(
					'Double extension detected (".%s." embedded in filename). This is a common cloaking technique.',
					$ext
				);
			}
		}
		return '';
	}

	/**
	 * Block oversized .ico files (likely webshells).
	 *
	 * @param string $filename Filename.
	 * @param int    $size     File size in bytes.
	 * @return string Block reason or empty string.
	 */
	private function check_ico_size( $filename, $size ) {
		$ext = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
		if ( 'ico' === $ext && $size > $this->ico_max_size ) {
			return sprintf(
				'Oversized .ico file (%s). Legitimate favicons are rarely larger than a few KB.',
				size_format( $size )
			);
		}
		return '';
	}

	/**
	 * Scan first 8 KB of the uploaded file for PHP open tags.
	 *
	 * @param string $tmp_path Temporary path.
	 * @param string $filename Original filename.
	 * @return string Block reason or empty string.
	 */
	private function check_php_content( $tmp_path, $filename ) {
		// Only check non-PHP files (PHP is already caught by extension check).
		$ext = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
		if ( in_array( $ext, $this->dangerous_extensions, true ) ) {
			return '';
		}

		if ( ! $tmp_path || ! @file_exists( $tmp_path ) ) {
			return '';
		}

		$handle = @fopen( $tmp_path, 'rb' );
		if ( ! $handle ) {
			return '';
		}
		$head = fread( $handle, 8192 );
		fclose( $handle );

		if ( false === $head ) {
			return '';
		}

		// Check for <?php opening tag (case-insensitive, word-boundary).
		// Note: We intentionally do NOT match short open tags (<?) because
		// they false-positive on XML declarations (<?xml) and are disabled
		// by default in modern PHP (short_open_tag = Off).
		if ( preg_match( '/<\?php\b/i', $head ) ) {
			return 'File contains PHP code (<?php tag detected in the first 8 KB). Non-PHP files must not contain executable code.';
		}

		return '';
	}

	/**
	 * Scan SVG uploads for script tags and event handlers.
	 *
	 * @param string $tmp_path Temporary path.
	 * @param string $filename Original filename.
	 * @return string Block reason or empty string.
	 */
	private function check_svg_xss( $tmp_path, $filename ) {
		$ext = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
		if ( 'svg' !== $ext ) {
			return '';
		}

		if ( ! $tmp_path || ! @file_exists( $tmp_path ) ) {
			return '';
		}

		$content = @file_get_contents( $tmp_path, false, null, 0, 65536 );
		if ( false === $content ) {
			return '';
		}

		$content_lower = strtolower( $content );

		// Script tags.
		if ( false !== strpos( $content_lower, '<script' ) ) {
			return 'SVG file contains a <script> tag. SVG uploads with embedded JavaScript are not allowed.';
		}

		// Event handler attributes.
		$event_handlers = array(
			'onload', 'onerror', 'onmouseover', 'onfocus', 'onclick',
			'onmouseenter', 'onmouseout', 'onanimationend', 'onbegin',
		);
		foreach ( $event_handlers as $handler ) {
			if ( preg_match( '/\b' . preg_quote( $handler, '/' ) . '\s*=/i', $content ) ) {
				return sprintf(
					'SVG file contains the "%s" event handler attribute. Inline event handlers enable XSS attacks.',
					$handler
				);
			}
		}

		// External resource loading via xlink:href with javascript:.
		if ( preg_match( '/xlink:href\s*=\s*["\']?\s*javascript:/i', $content ) ) {
			return 'SVG file contains a javascript: URI in xlink:href. This enables XSS attacks.';
		}

		return '';
	}

	/**
	 * Block an upload: check for override, log, and set error.
	 *
	 * @param array  $file         Upload data array.
	 * @param string $reason       Human-readable block reason.
	 * @param string $action       Machine action identifier.
	 * @param string $severity     Severity level.
	 * @param int    $user_id      Uploading user.
	 * @return array Modified $file with 'error' key set.
	 */
	private function block_upload( $file, $reason, $action, $severity, $user_id ) {
		$guard    = CleanShift_Guard::instance();
		$filename = isset( $file['name'] ) ? $file['name'] : '';

		// Check override before blocking.
		if ( $guard->override_manager->is_overridden( 'upload', $filename ) ) {
			$guard->audit_log->log(
				'upload',
				$action,
				'OVERRIDE',
				$severity,
				array(
					'filename' => $filename,
					'reason'   => $reason,
				),
				$user_id
			);
			return $file; // Allow through.
		}

		// Learning mode: log but don't block for first 48 hours.
		if ( $guard->is_learning_mode() ) {
			$guard->audit_log->log(
				'upload',
				$action,
				'LEARNING',
				$severity,
				array(
					'filename' => $filename,
					'reason'   => $reason,
					'note'     => 'Would have blocked — guard is in learning mode',
				),
				$user_id
			);
			return $file; // Allow through during learning.
		}

		// Block.
		$guard->audit_log->log(
			'upload',
			$action,
			'BLOCKED',
			$severity,
			array(
				'filename' => $filename,
				'reason'   => $reason,
			),
			$user_id
		);

		$file['error'] = '[CleanShift Guard] ' . $reason;
		return $file;
	}
}
