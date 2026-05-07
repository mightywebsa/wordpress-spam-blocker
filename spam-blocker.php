<?php
/*
Plugin Name: Spam Account Blocker
Description: Unified spam protection engine for registrations, logs, and IP blocking.
Author: Mightyweb Pty Ltd
Version: 1.5.2
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