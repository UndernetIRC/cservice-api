DELETE FROM variables
WHERE (var_name) IN (
                     'REQUIRED_SUPPORTERS',
                     'MAX_BAN_REASON_LENGTH',
                     'MAX_BANS',
                     'BAN_CHECK_ON_BURST',
                     'FLOOD_MESSAGES',
                     'FAILED_LOGINS',
                     'ALERT_FAILED_LOGINS',
                     'FAILED_LOGINS_RATE',
                     'MAX_FAILED_LOGINS',
                     'MAX_BAN_DURATION',
                     'LOGINS_FROM_SAME_IP',
                     'LOGINS_FROM_SAME_IP_AND_IDENT',
                     'USE_LOGIN_DELAY'
                    );
