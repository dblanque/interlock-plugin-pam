#!/usr/bin/env python3
# Deb packages: python3-pam python3-requests python3-pampy libpam-python
import signal
import sys
import syslog
import traceback
import os

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
if SCRIPT_PATH not in sys.path:
	sys.path.append(SCRIPT_PATH)
from pam_rest_config import PAM_REST_CONFIG  # noqa: E402
from PamRestApiAuthenticator import (  # noqa: E402
	PamRestApiAuthenticator,
	PamHandleProtocol,
	handle_pam_conv_response,
)

try:
	from pam.__internals import PAM_ABORT
except ImportError as e:
	syslog.syslog(syslog.LOG_ERR, f"PAM Import Error: {str(e)}")
	raise

PamHandle = PamHandleProtocol


# Handle CTRL+C Interrupt
def signal_handler(signal, frame):
	print("User cancelled authentication.")
	sys.exit(PAM_ABORT)


signal.signal(signal.SIGINT, signal_handler)


def pam_sm_authenticate(
	pamh: PamHandleProtocol, flags: int, argv: list[str]
) -> int:
	try:
		# Get and validate username first
		try:
			username = pamh.get_user(None)
		except pamh.exception as e:
			return e.pam_result
		if not username:
			return pamh.PAM_USER_UNKNOWN

		# Log authentication attempt with user
		syslog.syslog(
			syslog.LOG_INFO, f"PAM-REST: Authentication attempt for {username}"
		)

		# Get password
		password = None
		prompt = f"{PAM_REST_CONFIG.PROMPT_LABEL}: "
		try:
			msg = pamh.Message(prompt, pamh.PAM_PROMPT_ECHO_OFF)
		except TypeError:
			msg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, prompt)
		resp = handle_pam_conv_response(pamh.conversation([msg]))
		if resp:
			password = resp

		if not password:
			syslog.syslog(
				syslog.LOG_WARNING, f"PAM-REST: No password for {username}"
			)
			return pamh.PAM_AUTH_ERR
		# Initialize authenticator with PAM handle
		authenticator = PamRestApiAuthenticator(pamh=pamh)

		if not authenticator.authenticate(username, password):
			syslog.syslog(
				syslog.LOG_WARNING, f"PAM-REST: Auth failed for {username}"
			)
			return pamh.PAM_AUTH_ERR

		syslog.syslog(syslog.LOG_INFO, f"PAM-REST: Auth success for {username}")
		return pamh.PAM_SUCCESS

	except Exception as e:
		syslog.syslog(
			syslog.LOG_ERR,
			"PAM-REST: System error for %s: %s\n%s"
			% (
				username,
				str(e),
				traceback.print_exc(),
			),
		)
		return pamh.PAM_SYSTEM_ERR


def pam_sm_setcred(pamh: PamHandle, flags: int, argv: list[str]) -> int:
	"""PAM service function for setting credentials"""
	return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh: PamHandle, flags: int, argv: list[str]) -> int:
	"""PAM service function for account management"""
	return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh: PamHandle, flags: int, argv: list[str]) -> int:
	"""PAM service function for opening a session"""
	return pamh.PAM_SUCCESS


def pam_sm_close_session(pamh: PamHandle, flags: int, argv: list[str]) -> int:
	"""PAM service function for closing a session"""
	return pamh.PAM_SUCCESS


def pam_sm_chauthtok(pamh: PamHandle, flags: int, argv: list[str]) -> int:
	"""PAM service function for changing authentication tokens"""
	return pamh.PAM_SUCCESS
