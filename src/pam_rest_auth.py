#!/usr/bin/env python3
# Deb packages: python3-pam python3-requests python3-pampy libpam-python
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
)

PamHandle = PamHandleProtocol


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


		# Sudo uses on-login synced credentials
		if pamh.service == "sudo":
			syslog.syslog(
				syslog.LOG_INFO,
				"PAM-REST: SUDO attempt for user %s" % (
					username,
				)
			)
			return pamh.PAM_IGNORE

		# Log authentication attempt with user
		syslog.syslog(
			syslog.LOG_INFO,
			"PAM-REST: Authentication attempt for user %s (service: %s)" % (
				username,
				pamh.service,
			)
		)

		# Get password
		password = None
		prompt = f"{PAM_REST_CONFIG.PROMPT_LABEL}: "
		try:
			msg = pamh.Message(prompt, pamh.PAM_PROMPT_ECHO_OFF)
		except TypeError:
			msg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, prompt)

		# Password Conversation Handling
		try:
			resp = pamh.conversation([msg])
			if resp and hasattr(resp[0], "resp"):  # type: ignore
				password = resp[0].resp  # type: ignore
		except Exception as e:
			syslog.syslog(
				syslog.LOG_INFO, f"PAM-REST: Auth aborted for {username}"
			)
			syslog.syslog(
				syslog.LOG_ERR, f"PAM-REST: Auth abort error ({str(e)})"
			)
			return pamh.PAM_IGNORE

		if not password:
			syslog.syslog(
				syslog.LOG_WARNING, f"PAM-REST: No password for {username}"
			)
			return pamh.PAM_AUTH_ERR

		# Initialize authenticator with PAM handle
		authenticator = PamRestApiAuthenticator(pamh=pamh)
		authenticator.service = pamh.service

		# Perform authentication
		is_authenticated = authenticator.authenticate(username, password)
		if not is_authenticated:
			syslog.syslog(
				syslog.LOG_WARNING, f"PAM-REST: Auth failed for {username}"
			)
			return pamh.PAM_IGNORE

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
