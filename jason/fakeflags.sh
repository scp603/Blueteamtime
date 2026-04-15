#!/bin/bash
# Nine-Tailed Fox - Flag Hunter & Decoy Generator (v2)
# Focus: Finds CONFIDENTIAL{...} flags and deploys realistic, non-uniform decoys.

echo "=== Nine-Tailed Fox: Flag Decoy Operation ==="
echo "[+] Starting hunt for 'CONFIDENTIAL{' flags..."

SEARCH_DIRS="/root /home /var/www /opt /etc /tmp /usr/local"

FOUND_FILES=$(grep -rl "CONFIDENTIAL{" $SEARCH_DIRS 2>/dev/null)

if [ -z "$FOUND_FILES" ]; then
    echo "[-] No flags found in $SEARCH_DIRS."
    echo "    They might be in an unusual location, or named differently."
    exit 0
fi

# ---------------------------------------------------------------
# Dictionary of realistic-looking filenames (no numbers, varied)
# Based on observed competition naming patterns
# ---------------------------------------------------------------
FILENAMES=(
    "Q1_report"
    "Q2_report"
    "Q3_summary"
    "Q4_forecast"
    "wtf_happened_to_my_order"
    "PRIME_DAY_BABYYYY"
    "readme4fun"
    "amazon_app_secrets"
    "our_internal_config"
    "i_hate_report"
    "someone_say_export"
    "my_master_credentials"
    "prime_day_assets"
    "wp-config-backup"
    "amzn_admin_recovery"
    "stupid_company_handbook"
    "my_hr_records"
    "db_omega_master_supreme_key"
    "internal_engineering_notes"
    "amzn_store_access"
    "special_network_config"
    "fulfillment_summary"
    "db_backup_final"
    "service_account_keys"
    "internal_memo"
    "ops_runbook"
    "svc_credentials"
    "network_topology_notes"
    "deploy_secrets"
    "recovery_key_backup"
    "admin_panel_creds"
    "ssh_key_archive"
    "api_token_store"
    "customer_data_export"
    "db_user_dump"
    "server_migration_notes"
    "legacy_auth_config"
    "vpn_client_config"
    "internal_ca_cert"
    "bootstrap_secrets"
    "prod_env_vars"
    "staging_db_creds"
    "s3_bucket_keys"
    "iam_role_export"
    "cloudwatch_config"
    "jenkins_secrets"
    "ansible_vault_pass"
    "terraform_state_backup"
    "k8s_cluster_config"
    "docker_registry_auth"
    "nginx_vhost_config"
    "apache_ssl_config"
    "mysql_root_history"
    "redis_auth_tokens"
    "mongo_admin_creds"
    "postgres_dump"
    "ftp_user_listing"
    "smb_share_map"
    "ldap_bind_creds"
    "kerberos_keytab"
    "ad_sync_account"
    "exchange_service_pass"
    "backup_encryption_key"
    "offsite_backup_creds"
    "disaster_recovery_plan"
    "pentest_report_draft"
    "vuln_scan_results"
    "incident_notes"
    "soc_alert_export"
    "threat_intel_feed"
    "ioc_list"
    "asset_inventory"
    "firewall_ruleset_export"
    "switch_config_backup"
    "router_snmp_community"
    "wifi_psk_master"
    "vpn_preshared_keys"
    "cert_renewal_notes"
    "letsencrypt_account"
    "monitoring_api_keys"
    "splunk_forwarder_cfg"
    "elk_pipeline_config"
    "grafana_admin_pass"
    "pagerduty_token"
    "slack_webhook_secret"
    "jira_service_account"
    "confluence_admin_creds"
    "github_deploy_keys"
    "gitlab_runner_token"
    "sonarqube_token"
    "artifactory_api_key"
    "nexus_admin_pass"
    "vault_unseal_keys"
    "consul_acl_tokens"
    "nomad_cluster_creds"
    "etcd_auth_config"
    "zookeeper_digest"
    "kafka_sasl_config"
    "rabbitmq_admin"
    "celery_broker_url"
    "internal_dns_zones"
    "dhcp_lease_export"
    "netflow_collector_cfg"
)

# ---------------------------------------------------------------
# Dictionary of fake flag strings (leet speak, realistic format)
# ---------------------------------------------------------------
FAKE_FLAGS=(
    "CONFIDENTIAL{r3d1s_unauth_acc3ss_ftw}"
    "CONFIDENTIAL{cust0m3r_d4t4_3xf1ltr4t3d}"
    "CONFIDENTIAL{db_t4bl3_dump3d}"
    "CONFIDENTIAL{fl4sk_s3cr3t_k3y_3xp0s3d}"
    "CONFIDENTIAL{dns_z0n3_c0mpr0m1s3d}"
    "CONFIDENTIAL{4ct1v3_d1r3ct0ry_0wn3d}"
    "CONFIDENTIAL{l4t3r4l_m0v3m3nt_succ3ss}"
    "CONFIDENTIAL{smb_sh4r3_3xp0s3d}"
    "CONFIDENTIAL{sql_1nj3ct10n_s1r3n}"
    "CONFIDENTIAL{nt1m_h4sh_cr4ck3d}"
    "CONFIDENTIAL{priv3sc_v14_sudo_m1sc0nf1g}"
    "CONFIDENTIAL{ssh_k3y_h4rv3st3d}"
    "CONFIDENTIAL{w3bsh3ll_upl04d3d}"
    "CONFIDENTIAL{cr3d_dump_fr0m_lsass}"
    "CONFIDENTIAL{p4ssw0rd_spr4y_succ3ss}"
    "CONFIDENTIAL{s3cr3t_k3y_3xp0s3d_1n_g1t}"
    "CONFIDENTIAL{ftp_4n0n_4cc3ss_3n4bl3d}"
    "CONFIDENTIAL{r00t_sh3ll_obt41n3d}"
    "CONFIDENTIAL{b4ckd00r_1nst4ll3d}"
    "CONFIDENTIAL{r3v3rs3_sh3ll_c4ll3d_h0m3}"
    "CONFIDENTIAL{k3rn3l_3xpl01t_pr1v3sc}"
    "CONFIDENTIAL{p4ss_th3_h4sh_succ3ss}"
    "CONFIDENTIAL{g0ld3n_t1ck3t_f0rg3d}"
    "CONFIDENTIAL{dc_sync_att4ck_3x3cut3d}"
    "CONFIDENTIAL{s4ml_byp4ss_4ch13v3d}"
    "CONFIDENTIAL{s3_buck3t_3xp0s3d}"
    "CONFIDENTIAL{m3t4d4t4_s3rv1c3_4bus3d}"
    "CONFIDENTIAL{c0nt41n3r_3sc4p3_succ3ss}"
    "CONFIDENTIAL{cr0n_j0b_p3rs1st3nc3}"
    "CONFIDENTIAL{supp1y_ch41n_c0mpr0m1s3d}"
    "CONFIDENTIAL{0p3nvpn_k3ys_3xf1ltr4t3d}"
    "CONFIDENTIAL{m4n4g3m3nt_p0rt_4cc3ss3d}"
    "CONFIDENTIAL{t3ln3t_s3ss10n_h1j4ck3d}"
    "CONFIDENTIAL{4p1_k3y_h4rv3st3d}"
    "CONFIDENTIAL{db_cr3ds_1n_pl41nt3xt}"
    "CONFIDENTIAL{w0rdpr3ss_4dm1n_0wn3d}"
    "CONFIDENTIAL{ph9_c0d3_3x3cut10n}"
    "CONFIDENTIAL{n0_4uth_r3d1s_0wn3d}"
    "CONFIDENTIAL{smb_r3l4y_4tt4ck}"
    "CONFIDENTIAL{z3r0_d4y_3xpl01t3d}"
)

# ---------------------------------------------------------------
# File extensions to randomize (not just .txt)
# ---------------------------------------------------------------
EXTENSIONS=("txt")

echo "[!] Flags discovered:"
for FILE in $FOUND_FILES; do
    echo "  -> Found real flag file: $FILE"
    FLAG_DIR=$(dirname "$FILE")
    echo "  [+] Deploying 100 decoys in $FLAG_DIR..."

    # Track used names to avoid duplicates
    declare -A USED_NAMES

    COUNT=0
    ATTEMPTS=0
    while [ $COUNT -lt 100 ] && [ $ATTEMPTS -lt 500 ]; do
        ATTEMPTS=$((ATTEMPTS + 1))

        # Pick a random filename and extension
        RAND_NAME=${FILENAMES[$RANDOM % ${#FILENAMES[@]}]}
        RAND_EXT=${EXTENSIONS[$RANDOM % ${#EXTENSIONS[@]}]}
        FULL_NAME="${RAND_NAME}.${RAND_EXT}"

        # Skip if already used in this directory
        if [ "${USED_NAMES[$FULL_NAME]}" == "1" ]; then
            continue
        fi
        USED_NAMES[$FULL_NAME]=1

        # Pick a random fake flag
        FAKE_FLAG=${FAKE_FLAGS[$RANDOM % ${#FAKE_FLAGS[@]}]}

        echo "$FAKE_FLAG" > "$FLAG_DIR/$FULL_NAME"
        COUNT=$((COUNT + 1))
    done

    unset USED_NAMES
    echo "  [+] $COUNT decoys deployed in $FLAG_DIR."
    chmod 644 $FLAG_DIR/*.txt $FLAG_DIR/*.log $FLAG_DIR/*.bak $FLAG_DIR/*.conf 2>/dev/null
done

echo ""
echo "[+] Operation complete."
echo "[!] REMINDER: DO NOT move or edit the original flag file! (Rule #10)"