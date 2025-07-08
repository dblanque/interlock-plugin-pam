# Installation

## Server
1. Generate a key-pair by going to your Interlock installation directory and
executing the following commands:
```bash
. venv/bin/activate
python3 manage.py generate_pam_key
```
2. Keep the `SEND_ENCRYPTED` and `RECV_EXPECTED` values handy, you'll need them.

## Client
1. Copy `pam_rest_auth.py` to `/usr/share/interlock-plugin-pam/`
2. Give it the following permissions:
   1. `chmod 755 /usr/share/interlock-plugin-pam/`
   2. `chown root:root /usr/share/interlock-plugin-pam/`
3. Add the following line to `/etc/pam.d/common-auth`:
   * `auth    sufficient    pam_python.so /usr/share/interlock-plugin-pam/pam_rest_auth.py`
4. Install the following dependencies:
   ```apt install python3 python3-pam python3-requests python3-pampy libpam-python pamtester```
5. Edit your `/usr/share/interlock-plugin-pam/pam_rest_auth_conf.py` config file:
   1. Add your API URL as "API_URL=<your-api-url>".
   2. Add the `SEND_ENCRYPTED` and `RECV_EXPECTED` values from before.
6. Test authentication with `pamtester login $username authenticate`.
