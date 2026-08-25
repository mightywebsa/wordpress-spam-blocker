# Mightyweb Spam Blocker

A lightweight WordPress plugin designed to protect WordPress and Tutor LMS registration forms from common spam registrations and repeated abuse.

Spam Blocker uses keyword filtering, IP blacklisting, rate limiting, and detailed logging to stop unwanted registrations before they become a problem.

It is designed to be simple enough for a small WordPress website while providing useful tools for administrators managing larger or higher-risk registration systems.

---

## Features

### 🛡️ Spam Registration Protection

Spam Blocker can inspect registration information and block registrations containing configured spam keywords.

Keywords can be checked against:

- WordPress usernames
- WordPress email addresses
- Tutor LMS usernames
- Tutor LMS email addresses
- Tutor LMS display names

The keyword list can be managed directly from the WordPress admin area.

The default keyword list includes examples such as:

- `binance`
- `crypto`
- `forex`
- `bitcoin`
- `trading`
- `xtw`
- `transfer-btc`
- `btc`
- `.ru`
- `trade`
- `withdraw`

Administrators can add, remove, or replace keywords at any time.

---

## 🚫 IP Blacklisting

Spam Blocker automatically keeps track of repeated blocked attempts.

When an IP address reaches the configured threshold of blocked attempts, it can automatically be added to the blacklist.

Blacklisted IP addresses are rejected before the registration is processed.

Administrators can also:

- Add an IP manually
- Remove individual IP addresses
- Clear the entire blacklist
- Import large lists of IP addresses

Both IPv4 and IPv6 addresses are supported.

---

## ⚡ Rate Limiting

Spam Blocker includes rapid-registration protection.

The plugin monitors registration attempts from individual IP addresses and can temporarily block an IP when multiple registration attempts occur within a short period.

This helps protect against bots repeatedly submitting registration forms even when their username or email does not contain one of the configured keywords.

The rate-limit system works independently from the permanent IP blacklist.

---

## 📋 Bulk IP Import

Version 1.5.3 introduces bulk IP importing.

Administrators can add large numbers of IP addresses without manually entering them one at a time.

### Paste IP Addresses

IP addresses can be pasted directly into the WordPress admin area.

The importer supports:

- One IP per line
- Comma-separated IP addresses
- Space-separated IP addresses
- Tab-separated IP addresses
- Semicolon-separated IP addresses

Example:

    192.168.1.10
    192.168.1.20
    8.8.8.8
    2001:4860:4860::8888

---

### CSV Import

A CSV file can also be uploaded directly from the Spam Blocker administration page.

Example:

    IP
    8.8.8.8
    1.1.1.1
    192.168.1.50
    2001:4860:4860::8888

CSV files up to 10 MB are supported.

> Native Excel `.xlsx` files are not currently supported.
>
> Excel users can export their spreadsheet as CSV before importing it.

---

## 🔎 Import Validation

Every IP address submitted through the bulk importer is validated before being added to the blacklist.

The importer supports:

- IPv4
- IPv6

Invalid values are rejected.

For example:

    8.8.8.8              → Valid
    2001:4860:4860::8888 → Valid
    999.999.999.999      → Invalid
    hello                → Invalid

---

## ♻️ Duplicate Detection

The bulk importer automatically detects duplicate addresses.

Duplicates can occur in two ways.

### Duplicate within the import

For example:

    8.8.8.8
    1.1.1.1
    8.8.8.8

The second `8.8.8.8` will not be added again.

### Already blacklisted

If an IP is already present in the Spam Blocker blacklist, it will not be added again.

---

## 📊 Import Summary

After an import, Spam Blocker provides a summary showing exactly what happened.

Example:

    Bulk IP import complete.

    Processed:           1,005
    Added:                 950
    Already blacklisted:   40
    Duplicates:            10
    Invalid IPs:             5

Invalid IP addresses are also displayed so they can be reviewed and corrected.

---

## 📝 Spam Logging

Blocked registration attempts are recorded in:

    wp-content/spam-block-log.txt

Each entry contains information such as:

- Date and time
- Username
- Email address
- Triggered keyword
- IP address

Example:

    [2026-08-25 08:15:32] Blocked attempt:
    username='binance_trader',
    email='spam@example.com',
    pattern='binance',
    IP='192.168.1.100'

The log can be useful when determining which keywords or IP addresses should be added to the blacklist.

---

## ☁️ Cloudflare Support

Spam Blocker includes support for websites running behind Cloudflare.

When Cloudflare is present, the plugin checks:

    HTTP_CF_CONNECTING_IP

This allows the plugin to identify the visitor's actual IP rather than incorrectly blocking the Cloudflare proxy IP.

If Cloudflare is not being used, the plugin can fall back to forwarded/proxy information and ultimately the server's remote address.

---

## 🎓 Tutor LMS Support

Spam Blocker includes an integration with Tutor LMS registration validation.

When Tutor LMS is installed, the plugin can inspect Tutor LMS registrations in addition to standard WordPress registrations.

The Tutor LMS integration checks:

- Username
- Email address
- Display name
- IP blacklist
- Rate limiting
- Configured spam keywords

Tutor LMS is **not required** for the plugin to operate.

If Tutor LMS is not installed, the normal WordPress protection continues to work.

---

## ⚙️ Administration

After activation, a new menu item appears in WordPress:

**Spam Blocker**

The administration area provides access to:

### Blocked Keywords

Manage the keywords used to identify suspicious registrations.

Keywords are entered one per line.

Example:

    binance
    crypto
    forex
    bitcoin
    trading

Keyword matching is case-insensitive.

---

### Blacklisted IPs

The administrator can:

- Add individual IP addresses
- Remove individual IP addresses
- Clear the entire blacklist
- Import IP addresses in bulk

---

## 🔐 Security

Spam Blocker includes WordPress nonce protection for administrative actions.

Protected operations include:

- Saving keywords
- Adding IP addresses
- Removing IP addresses
- Clearing the blacklist
- Bulk IP imports
- CSV uploads

Administrative functions also require the WordPress:

    manage_options

capability.

This means normal WordPress users cannot access the Spam Blocker administration page.

---

## Requirements

### Required

- WordPress
- PHP version compatible with the installed WordPress version

### Optional

- Tutor LMS
- Cloudflare

Tutor LMS is not required.

Cloudflare is not required.

---

## Installation

### Standard WordPress Installation

1. Download the Spam Blocker plugin.
2. Upload the plugin ZIP through:

       WordPress Admin
       → Plugins
       → Add New
       → Upload Plugin

3. Activate **Spam Blocker**.
4. Open:

       WordPress Admin
       → Spam Blocker

5. Review the default blocked keywords.
6. Add any additional keywords required by the website.

---

### Manual Installation

Alternatively, copy the plugin directory into:

    /wp-content/plugins/

Then activate it through:

    WordPress Admin
    → Plugins

---

## Recommended Initial Configuration

After installing Spam Blocker, it is recommended to:

### 1. Review the keywords

Remove keywords that may cause legitimate registrations to be blocked.

Add keywords commonly appearing in spam registrations received by the website.

---

### 2. Monitor the log

Check:

    wp-content/spam-block-log.txt

This can help identify new spam patterns.

---

### 3. Review the blacklist

Regularly review automatically blocked IP addresses.

An IP can be removed from the blacklist if it has been blocked incorrectly.

---

### 4. Import known bad IP addresses

If you already maintain a list of known spam or abusive IP addresses, use the bulk import function rather than entering them individually.

---

## How the Protection Works

A typical registration follows this general process:

    Registration submitted
            ↓
    Determine visitor IP
            ↓
    Check IP blacklist
            ↓
    Check rate limit
            ↓
    Check configured keywords
            ↓
    Registration allowed
            OR
    Registration blocked
            ↓
    Blocked attempt logged
            ↓
    Repeated abuse may trigger IP blacklist

The same protection engine is used by the supported registration integrations.

---

## False Positives

Keyword blocking is intentionally simple and powerful, but administrators should be aware that a keyword may occasionally appear in a legitimate username or email address.

For example, if the keyword:

    trade

is blocked, an otherwise legitimate username containing `trade` could also be rejected.

If legitimate users are being blocked:

1. Check the Spam Blocker log.
2. Identify the keyword causing the block.
3. Remove or modify the keyword if necessary.
4. Remove the affected IP from the blacklist if appropriate.

---

## Important Notes

### IP Address Detection

Correct visitor IP detection depends on the website's hosting and proxy configuration.

Spam Blocker supports Cloudflare and common proxy headers, but administrators should verify that the detected IP addresses in the log are the actual visitor addresses.

---

### Shared IP Addresses

Automatic IP blacklisting should be used carefully on websites where many legitimate users may share the same public IP address.

Examples include:

- Schools
- Universities
- Corporate offices
- Public Wi-Fi
- Internet cafés
- Large residential networks

Blocking a shared IP can potentially affect multiple users.

---

### Rate Limiting

Rate limiting is designed primarily to slow down automated registration abuse.

It should not be considered a replacement for a full Web Application Firewall (WAF), CAPTCHA, or other security controls.

Spam Blocker is intended to work alongside normal WordPress security practices.

---

## Privacy

The Spam Blocker log may contain:

- IP addresses
- Usernames
- Email addresses
- Registration timestamps

Website administrators should ensure that their use of the plugin and its logs complies with applicable privacy legislation and their site's privacy policy.

For South African websites, administrators should consider their obligations under applicable POPIA requirements.

---

## File Structure

A typical installation contains the plugin files and supporting components used by the plugin.

The plugin stores its WordPress configuration using WordPress options rather than requiring a separate database table.

Important stored options include:

    spam_block_keywords
    spam_ip_blacklist

The spam activity log is stored at:

    wp-content/spam-block-log.txt

---

## Version History

### v1.5.3

**Bulk IP Import**

Added:

- Bulk IP paste functionality
- CSV IP import
- IPv4 validation
- IPv6 validation
- Duplicate detection
- Existing blacklist detection
- Import statistics
- Invalid IP reporting
- Secure import nonces
- CSV file validation
- 10 MB CSV upload limit

No changes were made to the existing registration protection engine or Tutor LMS/WordPress registration behaviour.

---

### v1.5.2

Architecture and administration improvements.

Includes:

- Centralised spam protection engine
- WordPress registration integration
- Tutor LMS integration
- IP blacklist management
- Keyword management
- Rate limiting
- Spam logging
- Cloudflare-aware IP detection
- Administrative security controls

---

### v1.3.1

Improved:

- IP detection
- Blacklist handling
- Administrative security
- Nonce protection
- IP management

---

### v1.3

Introduced:

- Rate limiting
- IP blacklist management
- Spam attempt logging
- Keyword management
- Tutor LMS registration protection

---

## Roadmap

Possible future features include:

- Native Excel `.xlsx` import
- CIDR/range blocking
- Country-based blocking
- Honeypot protection
- Improved reporting dashboard
- Spam statistics
- Search and filtering of blacklist entries
- Export blacklist
- Automatic log rotation
- Configurable rate-limit thresholds
- Configurable automatic blacklist thresholds
- Cloudflare API integration

---

## Support

Spam Blocker is developed by **Mightyweb**.

For support, bug reports, or feature requests, contact Mightyweb through the project's designated support channel.

---

## License

Copyright © Mightyweb Pty Ltd.

This plugin is distributed according to the license accompanying the project.

---

## Changelog

### 1.5.3
- Added bulk IP paste import.
- Added CSV IP import.
- Added IPv4 and IPv6 validation.
- Added duplicate detection.
- Added existing blacklist detection.
- Added import summaries.
- Added invalid IP reporting.
- Added nonce protection to bulk imports.
- Added CSV file validation.
- Added 10 MB CSV upload limit.
- No changes to WordPress registration behaviour.
- No changes to Tutor LMS registration behaviour.