# Installation from Source

## Documentation
Official python pam documentation:
* <https://pam-python.sourceforge.net/doc/html/>

## Server
1. Generate a key-pair by going to your Interlock installation directory and
executing the following commands:
```bash
. venv/bin/activate
python3 manage.py generate_pam_key
```
2. Keep the `SEND_ENCRYPTED` and `RECV_EXPECTED` values handy, you'll need them.

## Client
1. Clone this repository to a location of your choice (you may need to install `git`).
2. Copy the `./src` folder to `/usr/share/interlock-plugin-pam`.
3. Give it the following permissions:
   1. `chmod -R 750 /usr/share/interlock-plugin-pam/`
   2. `chown root:root /usr/share/interlock-plugin-pam/`
4. Add the following line to `/etc/pam.d/interlock-auth`:
   * `auth    sufficient    pam_python.so /usr/share/interlock-plugin-pam/pam_rest_auth.py`
5. Add the following line to `/etc/pam.d/common-auth`:
   * `@include interlock-auth`
6. Install the following dependencies:
   ```apt install python3 python3-pam python3-requests python3-pampy libpam-python pamtester```
7. Edit your `/usr/share/interlock-plugin-pam/config.ini` config file:
   1. Add your API URL as "API_URL=<your-api-url>".
   2. Add the `SEND_ENCRYPTED` and `RECV_EXPECTED` values from before.
8. Add user shell definitions to `/usr/share/interlock-plugin-pam/user_shells.ini` *(see sample file)*.
9. Test authentication with `pamtester login $username authenticate`.
