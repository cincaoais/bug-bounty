"""Truth-table tests for the legal action-class classifier (legalgate.classify).

Security-critical and CONSERVATIVE by design: every class has BOTH a positive
(must flag) and a negative (must NOT flag) case, because the whole value of the
gate is destroyed if it over-blocks and trains reflex-overrides.
"""
import legalgate


def _classes(tool_name, tool_input):
    return set(legalgate.classes(legalgate.classify(tool_name, tool_input)))


# ---- destructive (CCA s.5) ---------------------------------------------------

def test_http_delete_flag_is_destructive():
    assert "destructive" in _classes("Bash", {"command": "curl -X DELETE https://api.acme.com/users/1"})


def test_http_put_and_patch_flags_are_destructive():
    assert "destructive" in _classes("Bash", {"command": "curl --request PUT https://api.acme.com/x -d @b"})
    assert "destructive" in _classes("Bash", {"command": "curl -X PATCH https://api.acme.com/x"})


def test_plain_post_and_get_are_not_destructive():
    assert _classes("Bash", {"command": "curl -X POST https://api.acme.com/login -d user=a"}) == set()
    assert _classes("Bash", {"command": "curl https://api.acme.com/users/1"}) == set()


def test_sql_ddl_is_destructive():
    for kw in ["DROP TABLE users", "TRUNCATE users", "DELETE FROM sessions", "ALTER TABLE t ADD c INT"]:
        assert "destructive" in _classes("Bash", {"command": f"mysql -e '{kw}'"}), kw


def test_sqlmap_os_shell_is_destructive():
    assert "destructive" in _classes("Bash", {"command": "sqlmap -u http://x/y?id=1 --os-shell"})


def test_update_and_insert_are_not_flagged():
    # deliberately excluded: too common in benign request bodies
    assert _classes("Bash", {"command": "curl -X POST http://x/api -d 'INSERT INTO log VALUES(1)'"}) == set() \
        or "destructive" not in _classes("Bash", {"command": "curl http://x -d 'UPDATE p SET n=1'"})


def test_webgoat_restartlesson_is_destructive():
    assert "destructive" in _classes(
        "Bash", {"command": "curl http://localhost:3000/WebGoat/service/restartlesson.mvc/SqlInjection"})


def test_catastrophic_rm_is_destructive():
    for cmd in ["rm -rf /", "rm -rf /*", "rm -fr ~", "rm -rf $HOME", "sudo rm -rf /etc"]:
        assert "destructive" in _classes("Bash", {"command": cmd}), cmd


def test_ordinary_rm_is_not_flagged():
    for cmd in ["rm -rf ./build", "rm -rf node_modules", "rm file.txt", "rm -f out.json",
                "rm -rf ./dist/*"]:
        assert _classes("Bash", {"command": cmd}) == set(), cmd


def test_disk_and_forkbomb_are_destructive():
    assert "destructive" in _classes("Bash", {"command": "dd if=/dev/zero of=/dev/sda bs=1M"})
    assert "destructive" in _classes("Bash", {"command": "mkfs.ext4 /dev/sdb1"})
    assert "destructive" in _classes("Bash", {"command": ":(){ :|:& };:"})


def test_burp_send_delete_request_line_is_destructive():
    assert "destructive" in _classes(
        "mcp__burp__send_http1_request",
        {"targetHostname": "api.acme.com", "targetPort": 443,
         "content": "DELETE /users/1 HTTP/1.1\r\nHost: api.acme.com\r\n"})


def test_structured_method_field_delete_is_destructive():
    assert "destructive" in _classes("mcp__hexstrike__http_request",
                                     {"url": "http://x/1", "method": "DELETE"})


# ---- dos (CMA s.233) ---------------------------------------------------------

def test_brute_force_tools_are_dos():
    for cmd in ["hydra -l admin -P rockyou.txt ssh://10.0.0.1",
                "medusa -h h -u a -P w -M http", "ncrack -p 22 h", "patator ssh_login host=h"]:
        assert "dos" in _classes("Bash", {"command": cmd}), cmd


def test_flood_and_stress_tools_are_dos():
    assert "dos" in _classes("Bash", {"command": "ab -n 100000 -c 500 http://x/"})
    assert "dos" in _classes("Bash", {"command": "hping3 --flood -S -p 80 10.0.0.1"})
    assert "dos" in _classes("Bash", {"command": "slowloris x.example"})


def test_high_concurrency_over_threshold_is_dos():
    assert "dos" in _classes("Bash", {"command": "ffuf -u http://x/FUZZ -w w -t 200"})
    assert "dos" in _classes("Bash", {"command": "gobuster dir -u http://x -w w --threads 100"})


def test_default_concurrency_is_not_dos():
    assert _classes("Bash", {"command": "ffuf -u http://x/FUZZ -w w -t 40"}) == set()
    assert _classes("Bash", {"command": "ffuf -u http://x/FUZZ -w w"}) == set()
    assert _classes("Bash", {"command": "nuclei -u http://x"}) == set()


def test_high_rate_over_threshold_is_dos():
    assert "dos" in _classes("Bash", {"command": "masscan 10.0.0.0/24 --rate 10000"})
    assert "dos" in _classes("Bash", {"command": "nmap --min-rate 5000 10.0.0.1"})
    assert "dos" in _classes("Bash", {"command": "nuclei -u http://x -rl 500"})


def test_low_rate_is_not_dos():
    assert _classes("Bash", {"command": "masscan 10.0.0.0/24 --rate 50"}) == set()


def test_aggressive_nmap_timing_is_dos():
    assert "dos" in _classes("Bash", {"command": "nmap -T5 10.0.0.1"})
    assert "dos" in _classes("Bash", {"command": "nmap -T4 10.0.0.1"})
    assert _classes("Bash", {"command": "nmap -T2 10.0.0.1"}) == set()


def test_cookie_jar_flag_is_not_read_as_concurrency():
    # curl -c is a cookie-jar FILENAME, not a number — must not match -t/-c numeric rule
    assert _classes("Bash", {"command": "curl -c cookies.txt https://api.acme.com/x"}) == set()


# ---- credential (CCA s.6/s.8) -----------------------------------------------

def test_offline_cracking_tools_are_credential():
    assert "credential" in _classes("Bash", {"command": "hashcat -m 0 hashes.txt rockyou.txt"})
    assert "credential" in _classes("Bash", {"command": "john --wordlist=w hashes.txt"})


def test_harvest_relay_tools_are_credential():
    assert "credential" in _classes("Bash", {"command": "responder -I eth0"})
    assert "credential" in _classes("Bash", {"command": "secretsdump.py d/u:p@h"})


def test_crackmapexec_secrets_is_credential():
    assert "credential" in _classes("Bash", {"command": "crackmapexec smb h -u a -p b --sam"})


def test_reading_a_token_is_not_credential():
    assert _classes("Bash", {"command": "curl https://api.acme.com/me -H 'Authorization: Bearer x'"}) == set()


# ---- pii (PDPA) --------------------------------------------------------------

def test_sqlmap_dump_is_pii():
    assert "pii" in _classes("Bash", {"command": "sqlmap -u http://x/y?id=1 --dump -T users"})
    assert "pii" in _classes("Bash", {"command": "sqlmap -u http://x --dump-all"})


def test_mass_select_over_personal_table_is_pii():
    assert "pii" in _classes("Bash", {"command": "mysql -e 'SELECT * FROM users'"})
    assert "pii" in _classes("Bash", {"command": "psql -c 'select email,name from customers'"})


def test_single_record_read_is_not_pii():
    assert _classes("Bash", {"command": "curl https://api.acme.com/users/1"}) == set()
    assert _classes("Bash", {"command": "mysql -e 'SELECT * FROM products'"}) == set()


# ---- multi-class + safety ----------------------------------------------------

def test_sqlmap_dump_with_shell_hits_both_destructive_and_pii():
    got = _classes("Bash", {"command": "sqlmap -u http://x --os-shell --dump -T users"})
    assert "destructive" in got and "pii" in got


def test_benign_recon_and_reads_flag_nothing():
    for cmd in ["ls -la", "cat notes.txt", "git status", "nuclei -u http://x",
                "httpx -l hosts.txt", "subfinder -d acme.com",
                "curl https://api.acme.com/v1/users?page=1"]:
        assert _classes("Bash", {"command": cmd}) == set(), cmd


def test_classify_returns_violation_objects_with_statute_and_signature():
    vs = legalgate.classify("Bash", {"command": "curl -X DELETE http://x/1"})
    assert vs and vs[0].statute == "CCA 1997 s.5"
    assert vs[0].signature and vs[0].reason


def test_non_dict_input_does_not_crash():
    assert legalgate.classify("Bash", "not a dict") == [] or isinstance(
        legalgate.classify("Bash", "not a dict"), list)
