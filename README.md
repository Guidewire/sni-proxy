# sni-proxy

Simple reverse proxy written in go. Designed to provide SNI support for legacy systems.

# Configuration

```yml
certificate_crt_path: /etc/ssl/certs/cert1.crt
certificate_key_path: /etc/ssl/private/cert1.key
listen_https_address: ":433"
access_log: access.log
error_log: error.log
log_max_size_mb: 500
log_max_backups: 3
log_max_age_days: 20
pid_file: "sni-proxy.pid"
fix_header_names:
  X-Jenkins-Jnlp-Port: X-Jenkins-JNLP-Port
  X-Hudson-Jnlp-Port: X-Hudson-JNLP-Port
proxies:
  - hostname: host2
    target: "http://127.0.0.1:9000"
    certificate_crt_path: /etc/ssl/certs/host2.crt
    certificate_key_path: /etc/ssl/private/host2.key
  - hostname: "*"
    target: "http://127.0.0.1:8080"

```

Note that there's also an `listen_http_address` option but proxy will still add all the https X headers to these requests.
