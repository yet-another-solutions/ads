"""Provision only the two new databases and their deployment identity Secrets.

Run on the admin node. Credentials arrive as JSON on stdin, never argv.
No migrations, application rollout, or Keycloak Postgres changes.
"""
import json
import subprocess
import sys


def run(args, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError("Provisioning command failed; secret-bearing output suppressed")
    return result.stdout


def secret(namespace, name, data):
    run(["kubectl", "apply", "-f", "-"], json.dumps({
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"namespace": namespace, "name": name}, "type": "Opaque",
        "stringData": data,
    }))


def main():
    credentials = json.load(sys.stdin)
    psql = ["kubectl", "-n", "ads-postgres", "exec", "-i", "postgres-0", "--",
            "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "ads", "-d", "ads", "-At"]
    for component in ("mcp", "manager"):
        client = f"ads-sandbox-{component}"
        owner = client.replace("-", "_")
        password = credentials[client + "-db-credentials"]
        literal = "'" + password.replace("'", "''") + "'"
        exists = run(psql, f"SELECT 1 FROM pg_roles WHERE rolname='{owner}';").strip()
        command = "ALTER ROLE" if exists == "1" else "CREATE ROLE"
        run(psql, f"{command} {owner} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                  f"NOREPLICATION NOBYPASSRLS PASSWORD {literal};")
        exists = run(psql, f"SELECT 1 FROM pg_database WHERE datname='{owner}';").strip()
        if exists != "1":
            run(psql, f"CREATE DATABASE {owner} OWNER {owner};")
        actual_owner = run(psql, "SELECT pg_get_userbyid(datdba) FROM pg_database "
                                f"WHERE datname='{owner}';").strip()
        assert actual_owner == owner, "Refusing to change a foreign database owner"
        run(psql, f"REVOKE ALL ON DATABASE {owner} FROM PUBLIC; "
                  f"GRANT CONNECT ON DATABASE {owner} TO {owner};")
        check = run([
            "kubectl", "-n", "ads-postgres", "exec", "-i", "postgres-0", "--",
            "sh", "-c", 'IFS= read -r PGPASSWORD; export PGPASSWORD; '
            f'exec psql -X -h 127.0.0.1 -U {owner} -d {owner} -Atc '
            "'SELECT current_user,current_database();'",
        ], password + "\n")
        assert check.strip() == f"{owner}|{owner}"
        url = (f"postgresql+psycopg://{owner}:{password}"
               f"@postgres.ads-postgres.svc.cluster.local:5432/{owner}")
        secret("ads", client, {
            client.replace("-", "_").upper() + "_DATABASE_URL": url,
            client.replace("-", "_").upper() + "_KEYCLOAK_CLIENT_SECRET":
                credentials[client + "-oidc-client"],
        })
        print(f"PASS: {owner} database/login/owner and {client} Secret", flush=True)
    # IPC has no database. All instances mount the same client Secret.
    secret("ads-sandbox", "ads-sandbox-ipc", {
        "ADS_SANDBOX_IPC_KEYCLOAK_CLIENT_SECRET": credentials["ads-sandbox-ipc-oidc-client"],
    })
    print("PASS: shared IPC client Secret; no IPC database", flush=True)


if __name__ == "__main__":
    main()
