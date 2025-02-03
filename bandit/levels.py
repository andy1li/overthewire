import pwn


def run(conn: pwn.ssh, cmd: str):
    cat = conn.run(cmd)
    output = cat.recvall()
    try:
        print(output.decode())
    except UnicodeDecodeError:
        pass


def level_0(conn: pwn.ssh):
    run(conn, "cat readme")


def level_1(conn: pwn.ssh):
    run(conn, "cat ./-")


def level_2(conn: pwn.ssh):
    run(conn, "cat 'spaces in this filename'")


def level_3(conn: pwn.ssh):
    run(conn, "cat inhere/...Hiding-From-You")


def level_4(conn: pwn.ssh):
    run(
        conn,
        "find inhere -type f -exec file {} + | grep 'ASCII text' | cut -d: -f1 | xargs cat",
    )


def level_5(conn: pwn.ssh):
    run(
        conn,
        "find inhere -size 1033c ! -executable -exec file {} + | grep 'ASCII text' | cut -d: -f1 | xargs cat",
    )


def level_6(conn: pwn.ssh):
    run(
        conn,
        "find / -type f -user bandit7 -group bandit6 -size 33c 2> /dev/null | xargs cat",
    )


def level_7(conn: pwn.ssh):
    run(conn, "grep 'millionth' data.txt | awk '{print $2}'")


def level_8(conn: pwn.ssh):
    run(conn, "sort data.txt | uniq -u")


def level_9(conn: pwn.ssh):
    run(conn, "strings data.txt | grep -oE '=+ \\w+' | awk '{print $2}'")


def level_10(conn: pwn.ssh):
    run(conn, "base64 -d data.txt")


def level_11(conn: pwn.ssh):
    run(conn, "cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'")


def level_12(conn: pwn.ssh):
    run(
        conn,
        "cat data.txt | xxd -r | gzip -d | bzip2 -d | gzip -d | tar -xO | tar -xO | bzip2 -d | tar -xO | gzip -d",
    )


def level_13(conn: pwn.ssh):
    run(
        conn,
        "\
ssh -o StrictHostKeyChecking=no -i sshkey.private bandit14@localhost -p2220 \
cat /etc/bandit_pass/bandit14",
    )


def level_14(conn: pwn.ssh):
    run(conn, "cat /etc/bandit_pass/bandit14 | nc localhost 30000")


def level_15(conn: pwn.ssh):
    run(
        conn,
        f"cat /etc/bandit_pass/bandit15 | openssl s_client -connect localhost:30001 -quiet",
    )


def level_16(conn: pwn.ssh):
    run(
        conn,
        """\
open_ports=$(nmap -p 31000-32000 localhost | awk '/open/{print $1}' | cut -d'/' -f1)
for port in $open_ports; do
    output=$(cat /etc/bandit_pass/bandit16 | openssl s_client -connect localhost:$port -quiet 2> /dev/null)
    if [[ "$output" =~ ^Correct! ]]; then
        temp_file=$(mktemp)
        echo "$output" | tail -n +2 > "$temp_file"
        ssh -o StrictHostKeyChecking=no -i "$temp_file" bandit17@localhost -p2220 cat /etc/bandit_pass/bandit17
        break
    fi
done
""",
    )


def level_17(conn: pwn.ssh):
    run(conn, "diff passwords.{new,old} | grep '<' | awk '{print $2}'")


def level_18(conn: pwn.ssh):
    run(
        conn,
        "cat readme",
    )


def level_19(conn: pwn.ssh):
    run(conn, "./bandit20-do cat /etc/bandit_pass/bandit20")


def level_20(conn: pwn.ssh):
    run(conn, "")
