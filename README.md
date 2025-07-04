# Installation

1. Copy `pam_rest_auth.py` to `/usr/share/pam-python/`
2. Give it the following permissions:
   1. `chmod 755 /usr/share/pam-python/`
   2. `chown root:root /usr/share/pam-python/`
3. Add the following line to `/etc/pam.d/common-auth`:
   * `auth    sufficient    pam_python.so /usr/share/pam-python/pam_rest_auth.py`
4. Install the following dependencies:
   ```apt install python3 python3-pam python3-requests python3-pampy libpam-python pamtester```
5. Add your API Url as "API_URL=<your-api-url>" in `/usr/share/pam-python/pam_rest_auth_conf.py`
6. Test authentication with `pamtester login $username authenticate`.