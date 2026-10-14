import os
import paramiko

HOST = "192.168.56.101"
USER = "agent_soc"
KEY = os.path.expanduser(r"~\.ssh\soc_agent_key")

def run_fixed_command(cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, key_filename=KEY, timeout=10,
                   allow_agent=False, look_for_keys=False)
    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=15)
        return stdout.read().decode(), stderr.read().decode()
    finally:
        client.close()

if __name__ == "__main__":
    out, err = run_fixed_command("tail -n 20 /var/log/auth.log")
    print(out)
    if err:
        print("ERR:", err)
    out, err = run_fixed_command('grep -E "Failed password|Invalid user" /var/log/auth.log | tail -n 20')
    print(out)
    if err:
        print("ERR:", err)