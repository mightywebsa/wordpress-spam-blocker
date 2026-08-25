<?php
/*
Plugin Name: Spam Account Blocker
Description: Unified spam protection engine for registrations, logs, and IP blocking.
Author: Mightyweb Pty Ltd
Version: 1.5.3
License: GPL-3.0+
Text Domain: spam-blocker
*/

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// ======================================================
// 0. ACTIVATION HOOK — secure log directory
// ======================================================

register_activation_hook(__FILE__, 'spam_block_activate');

function spam_block_activate() {

    $log_dir = WP_CONTENT_DIR . '/spam-logs/';

    if ( ! file_exists( $log_dir ) ) {
        wp_mkdir_p( $log_dir );
    }

    // Block direct browser access to the entire directory
    $htaccess = $log_dir . '.htaccess';
    if ( ! file_exists( $htaccess ) ) {
        file_put_contents( $htaccess, "Order Deny,Allow\nDeny from all\n" );
    }

    // Also drop an empty index file as a second layer of protection
    $index = $log_dir . 'index.php';
    if ( ! file_exists( $index ) ) {
        file_put_contents( $index, "<?php // Silence is golden.\n" );
    }
}

// ======================================================
// 1. CORE ENGINE
// ======================================================

class Spam_Blocker_Engine {

    public static function check( $data ) {

        $ip       = self::get_ip();
        $keywords = self::get_keywords();

        // Normalize input
        $username = strtolower( trim( $data['username']     ?? '' ) );
        $email    = strtolower( trim( $data['email']        ?? '' ) );
        $display  = strtolower( trim( $data['display_name'] ?? '' ) );

        // 1. IP blacklist
        if ( self::is_blacklisted( $ip ) ) {
            return self::fail( 'ip_blocked', 'Your IP has been blocked.' );
        }

        // 2. Rate limit — increment ONCE, then check
        self::increment_rate( $ip );

        if ( self::rate_limit_exceeded( $ip ) ) {
            return self::fail( 'rate_limit', 'Too many attempts. Try again later.' );
        }

        // 3. Keyword checks
        foreach ( $keywords as $pattern ) {

            $pattern = strtolower( trim( $pattern ) );

            if ( $pattern === '' ) continue;

            if ( str_contains( $username, $pattern ) ) {
                self::log( $data, $pattern, $ip );
                return self::fail( 'username_blocked', "Username contains blocked keyword: $pattern" );
            }

            if ( str_contains( $email, $pattern ) ) {
                self::log( $data, $pattern, $ip );
                return self::fail( 'email_blocked', "Email contains blocked keyword: $pattern" );
            }

            if ( str_contains( $display, $pattern ) ) {
                self::log( $data, $pattern, $ip );
                return self::fail( 'display_blocked', "Display name contains blocked keyword: $pattern" );
            }
        }

        return [ 'pass' => true ];
    }

    // -------------------------
    // RESULT HELPERS
    // -------------------------
    private static function fail( $code, $message ) {
        return [
            'pass'    => false,
            'code'    => $code,
            'message' => $message,
        ];
    }

    // -------------------------
    // IP DETECTION
    // -------------------------
    private static function get_ip() {

        // Only trust CF header if the request actually comes from a Cloudflare IP.
        // Falls back gracefully on non-CF servers so the header can't be spoofed.
        if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && self::is_cloudflare_ip( $_SERVER['REMOTE_ADDR'] ?? '' ) ) {
            return sanitize_text_field( $_SERVER['HTTP_CF_CONNECTING_IP'] );
        }

        if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $ip_list = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
            return sanitize_text_field( trim( $ip_list[0] ) );
        }

        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * Lightweight Cloudflare IP range check.
     * Covers the published IPv4 ranges as of 2024.
     * Update this list periodically or replace with a dynamic fetch.
     */
    private static function is_cloudflare_ip( $ip ) {

        $cf_ranges = [
            '103.21.244.0/22',  '103.22.200.0/22',  '103.31.4.0/22',
            '104.16.0.0/13',    '104.24.0.0/14',    '108.162.192.0/18',
            '131.0.72.0/22',    '141.101.64.0/18',  '162.158.0.0/15',
            '172.64.0.0/13',    '173.245.48.0/20',  '188.114.96.0/20',
            '190.93.240.0/20',  '197.234.240.0/22', '198.41.128.0/17',
        ];

        $long_ip = ip2long( $ip );
        if ( $long_ip === false ) return false;

        foreach ( $cf_ranges as $range ) {
            [ $subnet, $bits ] = explode( '/', $range );
            $mask = -1 << ( 32 - (int) $bits );
            if ( ( $long_ip & $mask ) === ( ip2long( $subnet ) & $mask ) ) {
                return true;
            }
        }

        return false;
    }

    // -------------------------
    // KEYWORDS
    // -------------------------
    private static function get_keywords() {
        return get_option( 'spam_block_keywords', [
            'binance', 'crypto', 'forex', 'bitcoin', 'trading',
            'xtw', 'transfer-btc', 'btc', '.ru', 'trade', 'withdraw',
        ] );
    }

    // -------------------------
    // BLACKLIST
    // -------------------------
    private static function is_blacklisted( $ip ) {
        return in_array( $ip, (array) get_option( 'spam_ip_blacklist', [] ), true );
    }

    // -------------------------
    // RATE LIMIT
    // -------------------------
    private static function rate_limit_exceeded( $ip ) {
        $key  = 'spam_rate_' . md5( $ip );
        $data = get_transient( $key );

        if ( ! $data ) return false;

        return ( $data['count'] >= 5 ); // 5 attempts per 2-minute window
    }

    private static function increment_rate( $ip ) {
        $key  = 'spam_rate_' . md5( $ip );
        $data = get_transient( $key );
        $now  = time();

        if ( ! $data || ( $now - $data['start'] ) > 120 ) {
            $data = [ 'count' => 1, 'start' => $now ];
        } else {
            $data['count']++;
        }

        set_transient( $key, $data, 120 );
    }

    // -------------------------
    // LOGGING + AUTO-BLACKLIST
    // -------------------------
    private static function log( $data, $pattern, $ip ) {

        // Write to the protected directory created on activation
        $log_dir = WP_CONTENT_DIR . '/spam-logs/';

        // Safety net: recreate directory + protection files if somehow missing
        if ( ! file_exists( $log_dir ) ) {
            spam_block_activate();
        }

        $file  = $log_dir . 'spam-block-log.txt';

        $entry = sprintf(
            "[%s] user=%s email=%s pattern=%s ip=%s\n",
            current_time( 'mysql' ),
            $data['username'] ?? '',
            $data['email']    ?? '',
            $pattern,
            $ip
        );

        error_log( $entry, 3, $file );

        // Track abuse count for this IP (resets daily)
        $key   = 'spam_attempts_' . md5( $ip );
        $count = (int) get_transient( $key );
        $count++;

        set_transient( $key, $count, DAY_IN_SECONDS );

        // Auto-blacklist after 3 keyword hits in one day
        if ( $count >= 3 ) {
            $list = (array) get_option( 'spam_ip_blacklist', [] );

            if ( ! in_array( $ip, $list, true ) ) {
                $list[] = $ip;
                update_option( 'spam_ip_blacklist', $list );
            }
        }
    }
}

// ======================================================
// 2. WORDPRESS ADAPTER
// ======================================================

add_filter( 'registration_errors', function ( $errors, $user, $email ) {

    $result = Spam_Blocker_Engine::check( [
        'username' => $user,
        'email'    => $email,
    ] );

    if ( ! $result['pass'] ) {
        $errors->add( $result['code'], $result['message'] );
    }

    return $errors;

}, 100, 3 );

// ======================================================
// 3. TUTOR LMS ADAPTER
// ======================================================

add_filter( 'tutor_user_register_validation_filter', function ( $errors, $data ) {

    $result = Spam_Blocker_Engine::check( [
        'username'     => $data['user_login']    ?? '',
        'email'        => $data['user_email']    ?? '',
        'display_name' => $data['display_name']  ?? '',
    ] );

    if ( ! $result['pass'] ) {
        $errors[] = $result['message'];
    }

    return $errors;

}, 100, 2 );

// ======================================================
// 4. ADMIN MENU
// ======================================================

add_action( 'admin_menu', function () {
    add_menu_page(
        'Spam Account Blocker',
        'Spam Account Blocker',
        'manage_options',
        'spam-blocker',
        'spam_block_admin_page',
        'dashicons-shield',
        80
    );
} );

// ======================================================
// 5. ADMIN PAGE
// ======================================================

// ======================================================
// BULK IP IMPORT HELPERS
// ======================================================

/**
 * Process a collection of IP addresses and add valid,
 * non-duplicate addresses to the blacklist.
 *
 * @param array $ips IP addresses to process.
 * @return array Import statistics.
 */
function spam_block_process_bulk_ips( $ips ) {

    $blacklist = array_values(
        array_filter(
            (array) get_option( 'spam_ip_blacklist', [] ),
            'is_string'
        )
    );

    $blacklist_lookup = array_fill_keys( $blacklist, true );

    $stats = [
        'processed'       => 0,
        'added'           => 0,
        'duplicates'      => 0,
        'already_blocked' => 0,
        'invalid'         => 0,
        'invalid_ips'     => [],
    ];

    $imported_this_batch = [];

    foreach ( $ips as $raw_ip ) {

        $ip = trim( $raw_ip );

        // Remove common CSV/text formatting.
        $ip = trim( $ip, "\"' \t\n\r\0\x0B" );

        if ( $ip === '' ) {
            continue;
        }

        $stats['processed']++;

        // Validate IPv4 or IPv6.
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {

            $stats['invalid']++;

            if ( count( $stats['invalid_ips'] ) < 100 ) {
                $stats['invalid_ips'][] = $ip;
            }

            continue;
        }

        // Duplicate within the same import.
        if ( isset( $imported_this_batch[ $ip ] ) ) {
            $stats['duplicates']++;
            continue;
        }

        $imported_this_batch[ $ip ] = true;

        // Already exists in blacklist.
        if ( isset( $blacklist_lookup[ $ip ] ) ) {
            $stats['already_blocked']++;
            continue;
        }

        // Add to blacklist.
        $blacklist[] = $ip;
        $blacklist_lookup[ $ip ] = true;

        $stats['added']++;
    }

    // Only update the database if something was actually added.
    if ( $stats['added'] > 0 ) {
        update_option( 'spam_ip_blacklist', $blacklist );
    }

    return $stats;
}


/**
 * Convert pasted text into individual IP addresses.
 *
 * Supports:
 * - One IP per line
 * - Comma separated
 * - Tab separated
 * - Spaces
 * - Semicolon separated
 */
function spam_block_parse_pasted_ips( $text ) {

    $text = wp_unslash( $text );

    return preg_split(
        '/[\s,;]+/',
        $text,
        -1,
        PREG_SPLIT_NO_EMPTY
    );
}


/**
 * Read IP addresses from an uploaded CSV file.
 *
 * Every CSV cell is checked, allowing CSV files with:
 *
 * IP
 * 192.168.1.1
 * 8.8.8.8
 *
 * or CSV files containing multiple columns.
 */
function spam_block_parse_csv( $file ) {

    $ips = [];

    if ( ! is_readable( $file ) ) {
        return $ips;
    }

    $handle = fopen( $file, 'r' );

    if ( false === $handle ) {
        return $ips;
    }

    while ( false !== ( $row = fgetcsv( $handle ) ) ) {

        foreach ( $row as $value ) {

            $value = trim( $value );

            if ( $value === '' ) {
                continue;
            }

            // Ignore common CSV header names.
            $header = strtolower( trim( $value ) );

            if ( in_array(
                $header,
                [ 'ip', 'ip address', 'ip_address', 'address', 'ipaddress' ],
                true
            ) ) {
                continue;
            }

            $ips[] = $value;
        }
    }

    fclose( $handle );

    return $ips;
}

function spam_block_admin_page() {

    if ( ! current_user_can( 'manage_options' ) ) return;

    echo '<div class="wrap"><h1>Spam Account Blocker v1.5.2</h1>';

    if (
        isset( $_GET['remove_ip'], $_GET['_wpnonce'] ) &&
        wp_verify_nonce( sanitize_text_field( $_GET['_wpnonce'] ), 'remove_ip_nonce' )
    ) {
        $ip_to_remove = sanitize_text_field( $_GET['remove_ip'] );
        $list         = array_values( array_filter(
            (array) get_option( 'spam_ip_blacklist', [] ),
            fn( $ip ) => $ip !== $ip_to_remove
        ) );

        update_option( 'spam_ip_blacklist', $list );

        // Also reset the abuse counter for this IP so it gets a clean slate
        delete_transient( 'spam_attempts_' . md5( $ip_to_remove ) );

        echo '<div class="updated"><p>IP <strong>' . esc_html( $ip_to_remove ) . '</strong> has been removed from the blacklist.</p></div>';
    }

    if ( isset( $_POST['save_keywords'] ) && wp_verify_nonce( $_POST['_wpnonce'], 'save_keywords_nonce' ) ) {

        $keywords_raw = sanitize_textarea_field( $_POST['spam_keywords'] );

        $keywords = array_values( array_unique( array_filter( array_map(
            fn( $k ) => strtolower( trim( $k ) ),
            explode( "\n", $keywords_raw )
        ) ) ) );

        update_option( 'spam_block_keywords', $keywords );

        echo '<div class="updated"><p>Keywords updated.</p></div>';
    }


    if ( isset( $_POST['add_ip'] ) && wp_verify_nonce( $_POST['_wpnonce_add_ip'], 'add_ip_nonce' ) ) {

        $new_ip = sanitize_text_field( trim( $_POST['new_ip'] ?? '' ) );

        if ( filter_var( $new_ip, FILTER_VALIDATE_IP ) ) {
            $list = (array) get_option( 'spam_ip_blacklist', [] );

            if ( ! in_array( $new_ip, $list, true ) ) {
                $list[] = $new_ip;
                update_option( 'spam_ip_blacklist', $list );
                echo '<div class="updated"><p>IP <strong>' . esc_html( $new_ip ) . '</strong> added to the blacklist.</p></div>';
            } else {
                echo '<div class="notice notice-warning"><p>That IP is already blacklisted.</p></div>';
            }
        } else {
            echo '<div class="notice notice-error"><p>Invalid IP address entered.</p></div>';
        }
    }

    // ======================================================
    // BULK IP IMPORT
    // ======================================================

    // --------------------------------------------------
    // Paste bulk IPs
    // --------------------------------------------------
    if (
        isset( $_POST['bulk_import_ips'] ) &&
        isset( $_POST['_wpnonce_bulk_ips'] ) &&
        wp_verify_nonce(
            sanitize_text_field( wp_unslash( $_POST['_wpnonce_bulk_ips'] ) ),
            'bulk_import_ips_nonce'
        )
    ) {

        $raw_ips = $_POST['bulk_ips'] ?? '';

        $ips = spam_block_parse_pasted_ips( $raw_ips );

        $stats = spam_block_process_bulk_ips( $ips );

        echo '<div class="notice notice-success is-dismissible">';
        echo '<p><strong>Bulk IP import complete.</strong></p>';
        echo '<ul style="margin-left:20px;">';

        echo '<li>Processed: <strong>' . esc_html( $stats['processed'] ) . '</strong></li>';
        echo '<li>Added: <strong>' . esc_html( $stats['added'] ) . '</strong></li>';
        echo '<li>Already blacklisted: <strong>' . esc_html( $stats['already_blocked'] ) . '</strong></li>';
        echo '<li>Duplicates in import: <strong>' . esc_html( $stats['duplicates'] ) . '</strong></li>';
        echo '<li>Invalid IPs: <strong>' . esc_html( $stats['invalid'] ) . '</strong></li>';

        echo '</ul>';
        echo '</div>';

        if ( ! empty( $stats['invalid_ips'] ) ) {

            echo '<div class="notice notice-warning">';
            echo '<p><strong>Invalid IP addresses:</strong></p>';
            echo '<textarea readonly style="width:100%;height:100px;font-family:monospace;">'
                . esc_textarea( implode( "\n", $stats['invalid_ips'] ) )
                . '</textarea>';

            if ( $stats['invalid'] > 100 ) {
                echo '<p>Only the first 100 invalid addresses are displayed.</p>';
            }

            echo '</div>';
        }
    }


    // --------------------------------------------------
    // CSV upload
    // --------------------------------------------------
    if (
        isset( $_POST['bulk_import_csv'] ) &&
        isset( $_POST['_wpnonce_bulk_csv'] ) &&
        wp_verify_nonce(
            sanitize_text_field( wp_unslash( $_POST['_wpnonce_bulk_csv'] ) ),
            'bulk_import_csv_nonce'
        )
    ) {

        $stats = [
            'processed'       => 0,
            'added'           => 0,
            'duplicates'      => 0,
            'already_blocked' => 0,
            'invalid'         => 0,
            'invalid_ips'     => [],
        ];

        if (
            ! isset( $_FILES['spam_csv'] ) ||
            empty( $_FILES['spam_csv']['tmp_name'] )
        ) {

            echo '<div class="notice notice-error">';
            echo '<p>Please select a CSV file to upload.</p>';
            echo '</div>';

        } else {

            $file = $_FILES['spam_csv'];

            // Maximum upload size: 10 MB.
            if ( $file['size'] > 10 * MB_IN_BYTES ) {

                echo '<div class="notice notice-error">';
                echo '<p>The CSV file is too large. Maximum size is 10 MB.</p>';
                echo '</div>';

            } elseif ( UPLOAD_ERR_OK !== (int) $file['error'] ) {

                echo '<div class="notice notice-error">';
                echo '<p>There was a problem uploading the CSV file.</p>';
                echo '</div>';

            } else {

                $extension = strtolower(
                    pathinfo( $file['name'], PATHINFO_EXTENSION )
                );

                if ( 'csv' !== $extension ) {

                    echo '<div class="notice notice-error">';
                    echo '<p>Only CSV files are supported.</p>';
                    echo '</div>';

                } else {

                    $ips = spam_block_parse_csv( $file['tmp_name'] );

                    $stats = spam_block_process_bulk_ips( $ips );

                    echo '<div class="notice notice-success is-dismissible">';
                    echo '<p><strong>CSV import complete.</strong></p>';
                    echo '<ul style="margin-left:20px;">';

                    echo '<li>Processed: <strong>' . esc_html( $stats['processed'] ) . '</strong></li>';
                    echo '<li>Added: <strong>' . esc_html( $stats['added'] ) . '</strong></li>';
                    echo '<li>Already blacklisted: <strong>' . esc_html( $stats['already_blocked'] ) . '</strong></li>';
                    echo '<li>Duplicates in import: <strong>' . esc_html( $stats['duplicates'] ) . '</strong></li>';
                    echo '<li>Invalid IPs: <strong>' . esc_html( $stats['invalid'] ) . '</strong></li>';

                    echo '</ul>';
                    echo '</div>';

                    if ( ! empty( $stats['invalid_ips'] ) ) {

                        echo '<div class="notice notice-warning">';
                        echo '<p><strong>Invalid IP addresses:</strong></p>';

                        echo '<textarea readonly style="width:100%;height:100px;font-family:monospace;">'
                            . esc_textarea( implode( "\n", $stats['invalid_ips'] ) )
                            . '</textarea>';

                        if ( $stats['invalid'] > 100 ) {
                            echo '<p>Only the first 100 invalid addresses are displayed.</p>';
                        }

                        echo '</div>';
                    }
                }
            }
        }
    }

    // --------------------------------------------------
    // FETCH current data
    // --------------------------------------------------
    $keywords  = get_option( 'spam_block_keywords', [] );
    $blacklist = get_option( 'spam_ip_blacklist', [] );

    // --------------------------------------------------
    // SECTION: Keywords
    // --------------------------------------------------
    echo '<h2>Blocked Keywords</h2>';
    echo '<form method="post">';
    wp_nonce_field( 'save_keywords_nonce' );

    echo '<p style="color:#666;">One keyword per line. Matching is case-insensitive substring.</p>';
    echo '<textarea name="spam_keywords" style="width:100%;height:150px;font-family:monospace;">'
        . esc_textarea( implode( "\n", $keywords ) )
        . '</textarea>';

    echo '<p><button class="button button-primary" name="save_keywords">Save Keywords</button></p>';
    echo '</form><hr>';

    // --------------------------------------------------
    // SECTION: Blacklisted IPs
    // --------------------------------------------------
    echo '<h2>Blacklisted IPs</h2>';

    // Manual add form
    echo '<form method="post" style="margin-bottom:16px;">';
    wp_nonce_field( 'add_ip_nonce', '_wpnonce_add_ip' );
    echo '<input type="text" name="new_ip" placeholder="e.g. 192.168.1.100" style="width:220px;" />';
    echo ' <button class="button" name="add_ip">Add IP Manually</button>';
    echo '</form>';

    // --------------------------------------------------
    // BULK IP IMPORT
    // --------------------------------------------------

    echo '<div style="
        background:#fff;
        border:1px solid #ccd0d4;
        padding:20px;
        margin:20px 0;
        max-width:900px;
    ">';

    echo '<h3 style="margin-top:0;">Bulk Import IP Addresses</h3>';

    echo '<p>';
    echo 'Add multiple IPv4 or IPv6 addresses at once. ';
    echo 'Existing blacklisted IPs and duplicates will automatically be skipped.';
    echo '</p>';


    // --------------------------------------------------
    // Paste IPs
    // --------------------------------------------------

    echo '<h4>Paste IP Addresses</h4>';

    echo '<form method="post">';

    wp_nonce_field(
        'bulk_import_ips_nonce',
        '_wpnonce_bulk_ips'
    );

    echo '<textarea
        name="bulk_ips"
        rows="10"
        style="
            width:100%;
            max-width:800px;
            font-family:monospace;
            font-size:13px;
        "
        placeholder="192.168.1.10
    192.168.1.20
    8.8.8.8
    2001:4860:4860::8888
    2001:db8::1
    "></textarea>';

    echo '<p class="description">';
    echo 'One IP per line, or separate addresses with commas, spaces, tabs or semicolons.';
    echo '</p>';

    echo '<p>';
    echo '<button
        type="submit"
        name="bulk_import_ips"
        class="button button-primary"
    >';
    echo 'Import IP Addresses';
    echo '</button>';
    echo '</p>';

    echo '</form>';


    // --------------------------------------------------
    // CSV Upload
    // --------------------------------------------------

    echo '<hr>';

    echo '<h4>Upload CSV File</h4>';

    echo '<p>';
    echo 'Upload a CSV file containing IP addresses. ';
    echo 'Excel files (.xlsx) are not supported in this version.';
    echo '</p>';

    echo '<form
        method="post"
        enctype="multipart/form-data"
    >';

    wp_nonce_field(
        'bulk_import_csv_nonce',
        '_wpnonce_bulk_csv'
    );

    echo '<input
        type="file"
        name="spam_csv"
        accept=".csv,text/csv"
    >';

    echo '<p class="description">';
    echo 'Maximum file size: 10 MB. IPv4 and IPv6 are supported.';
    echo '</p>';

    echo '<p>';
    echo '<button
        type="submit"
        name="bulk_import_csv"
        class="button"
    >';
    echo 'Import CSV';
    echo '</button>';
    echo '</p>';

    echo '</form>';

    echo '</div>';

    if ( empty( $blacklist ) ) {
        echo '<p>No IPs currently blocked.</p>';
    } else {

        $count = count( $blacklist );
        echo '<p>' . esc_html( $count ) . ' IP' . ( $count !== 1 ? 's' : '' ) . ' currently blocked.</p>';

        echo '<table class="widefat striped">';
        echo '<thead><tr><th>#</th><th>IP Address</th><th>Action</th></tr></thead>';
        echo '<tbody>';

        foreach ( $blacklist as $index => $ip ) {

            $remove_url = wp_nonce_url(
                add_query_arg( [
                    'page'      => 'spam-blocker',
                    'remove_ip' => urlencode( $ip ),
                ], admin_url( 'admin.php' ) ),
                'remove_ip_nonce'
            );

            echo '<tr>';
            echo '<td>' . esc_html( $index + 1 ) . '</td>';
            echo '<td>' . esc_html( $ip ) . '</td>';
            echo '<td><a class="button button-small" href="' . esc_url( $remove_url ) . '" '
                . 'onclick="return confirm(\'Remove ' . esc_js( $ip ) . ' from the blacklist?\');">'
                . 'Remove</a></td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }   
    echo '</div>'; // .wrap
}