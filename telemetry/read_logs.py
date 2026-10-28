import os
import paramiko
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("SSH_HOST", "192.168.56.101")
PORT = int(os.getenv("SSH_PORT", "22"))
USER = os.getenv("SSH_USER", "agent_soc")
KEY = os.path.expanduser(os.getenv("SSH_KEY_PATH", r"~\.ssh\soc_agent_key"))
PASSWORD = os.getenv("SSH_PASSWORD", None)


def run_fixed_command(cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    connect_kwargs = {
        "hostname": HOST,
        "port": PORT,
        "username": USER,
        "timeout": 10,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if PASSWORD:
        connect_kwargs["password"] = PASSWORD
    else:
        connect_kwargs["key_filename"] = KEY

    client.connect(**connect_kwargs)
    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=15)
        return stdout.read().decode(errors="replace"), stderr.read().decode(errors="replace")
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