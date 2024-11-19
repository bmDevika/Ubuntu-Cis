#!/bin/bash

# Output file where the results will be stored
output_file="cis_compliance_report.txt"

# Clear the output file before starting
echo "CIS Compliance Check Report" > "$output_file"
echo "Generated on $(date)" >> "$output_file"
echo "--------------------------------------------------------" >> "$output_file"

# Define a function to compare the command output with the expected result
compare_output() {
    test_case="$1"
    command="$2"
    expected_output="$3"

    echo "Running Test Case: $test_case"

    # Execute the command and capture the actual output
    actual_output=$(eval "$command" 2>&1)

    # Append the result to the output file in the required format
    echo "Test Case: $test_case" >> "$output_file"
    echo "Expected Output: $expected_output" >> "$output_file"
    echo "Actual Output: $actual_output" >> "$output_file"
    echo "--------------------------------------------------------" >> "$output_file"

    # Display results to the console for immediate feedback
    echo "Test Case: $test_case"
    echo "Expected Output: $expected_output"
    echo "Actual Output: $actual_output"
    echo "--------------------------------------------------------"
}

# Test cases and their corresponding commands and expected outputs

# 4.1.3 Ensure default deny firewall policy
compare_output "4.1.3 Ensure default deny firewall policy" \
    "ufw default deny" \
    "Default deny rule for incoming traffic"

# 4.1.4 Ensure that loopback traffic is allowed
compare_output "4.1.4 Ensure that loopback traffic is allowed" \
    "ufw allow from 127.0.0.1" \
    "Allow loopback traffic"

# 4.1.5 Ensure outbound connections are limited
compare_output "4.1.5 Ensure outbound connections are limited" \
    "ufw default allow outgoing" \
    "Allow outgoing traffic"

# 4.1.6 Ensure firewall rules are applied to all interfaces
compare_output "4.1.6 Ensure firewall rules are applied to all interfaces" \
    "ufw enable" \
    "Firewall rules applied to all interfaces"

# 4.1.7 Ensure firewall is active
compare_output "4.1.7 Ensure firewall is active" \
    "ufw status" \
    "active"

# 5.1.1 Ensure permissions on bootloader config are configured
compare_output "5.1.1 Ensure permissions on bootloader config are configured" \
    "stat /etc/default/grub" \
    "Permissions should be rw-r--r--"

# 5.1.2 Ensure bootloader password is set
compare_output "5.1.2 Ensure bootloader password is set" \
    "grep -i 'GRUB_PASSWORD' /etc/default/grub" \
    "GRUB_PASSWORD"

# 5.1.3 Ensure additional bootloader security options are configured
compare_output "5.1.3 Ensure additional bootloader security options are configured" \
    "grep -i 'GRUB_DISABLE_RECOVERY' /etc/default/grub" \
    "GRUB_DISABLE_RECOVERY=true"

# 5.2.1 Ensure no unnecessary services are running
compare_output "5.2.1 Ensure no unnecessary services are running" \
    "systemctl list-units --type=service --state=running" \
    "Only necessary services should be running"

# 5.2.2 Ensure no unnecessary services are enabled
compare_output "5.2.2 Ensure no unnecessary services are enabled" \
    "systemctl list-unit-files --state=enabled" \
    "Only necessary services should be enabled"

# 6.1.1 Ensure permissions on /etc/passwd are configured
compare_output "6.1.1 Ensure permissions on /etc/passwd are configured" \
    "stat /etc/passwd" \
    "Permissions should be rw-r--r--"

# 6.1.2 Ensure permissions on /etc/shadow are configured
compare_output "6.1.2 Ensure permissions on /etc/shadow are configured" \
    "stat /etc/shadow" \
    "Permissions should be rw-r-----"

# 6.1.3 Ensure permissions on /etc/group are configured
compare_output "6.1.3 Ensure permissions on /etc/group are configured" \
    "stat /etc/group" \
    "Permissions should be rw-r--r--"

# 6.1.4 Ensure permissions on /etc/gshadow are configured
compare_output "6.1.4 Ensure permissions on /etc/gshadow are configured" \
    "stat /etc/gshadow" \
    "Permissions should be rw-r-----"

# 6.2.1 Ensure password expiration is configured
compare_output "6.2.1 Ensure password expiration is configured" \
    "chage -l root" \
    "Password expiry should be configured"

# 6.2.2 Ensure password complexity is configured
compare_output "6.2.2 Ensure password complexity is configured" \
    "grep -E '^PASS_' /etc/login.defs" \
    "PASS_MIN_DAYS, PASS_MAX_DAYS, PASS_WARN_AGE"

# 6.2.3 Ensure password history is configured
compare_output "6.2.3 Ensure password history is configured" \
    "grep -E '^password required pam_unix.so' /etc/pam.d/common-password" \
    "password required pam_unix.so remember=5"

# 6.2.4 Ensure account lockout for failed login attempts is configured
compare_output "6.2.4 Ensure account lockout for failed login attempts is configured" \
    "grep pam_tally2 /etc/pam.d/common-auth" \
    "pam_tally2"

# 7.1.1 Ensure auditd service is installed
compare_output "7.1.1 Ensure auditd service is installed" \
    "dpkg -l | grep auditd" \
    "auditd installed"

# 7.1.2 Ensure auditd service is enabled
compare_output "7.1.2 Ensure auditd service is enabled" \
    "systemctl is-enabled auditd" \
    "enabled"

# 7.1.3 Ensure auditd service is running
compare_output "7.1.3 Ensure auditd service is running" \
    "systemctl is-active auditd" \
    "active"

# 7.2.1 Ensure audit logs are being collected
compare_output "7.2.1 Ensure audit logs are being collected" \
    "grep -i 'log_file' /etc/audit/auditd.conf" \
    "log_file = /var/log/audit/audit.log"

# 7.2.2 Ensure auditd configuration is correct
compare_output "7.2.2 Ensure auditd configuration is correct" \
    "grep -i 'max_log_file' /etc/audit/auditd.conf" \
    "max_log_file = 6"

# 7.2.3 Ensure audit log retention is configured
compare_output "7.2.3 Ensure audit log retention is configured" \
    "grep -i 'max_log_file_action' /etc/audit/auditd.conf" \
    "max_log_file_action = ROTATE"

# 7.2.4 Ensure auditd is configured to retain logs
compare_output "7.2.4 Ensure auditd is configured to retain logs" \
    "grep -i 'space_left_action' /etc/audit/auditd.conf" \
    "space_left_action = SYSLOG"

# 7.2.5 Ensure audit log file permissions are configured
compare_output "7.2.5 Ensure audit log file permissions are configured" \
    "stat /var/log/audit/audit.log" \
    "Permissions should be rw-------"

# 7.2.6 Ensure audit logs are immutable
compare_output "7.2.6 Ensure audit logs are immutable" \
    "auditctl -e 2" \
    "audit logs should be immutable"

# 7.2.7 Ensure audit log storage is separate from root
compare_output "7.2.7 Ensure audit log storage is separate from root" \
    "df /var/log/audit" \
    "Audit logs should not be stored on the root partition"

# 7.2.8 Ensure audit logs are rotated
compare_output "7.2.8 Ensure audit logs are rotated" \
    "grep -i 'rotate' /etc/audit/auditd.conf" \
    "rotate = 7"

# End of the script
echo "CIS Compliance Check completed. Results are stored in $output_file"