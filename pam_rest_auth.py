#!/usr/bin/env python3
# Deb packages: python3-pam python3-requests python3-pampy libpam-python
import json
import requests
import signal
import sys
import syslog
from typing import Protocol, Optional, Any
import traceback
import subprocess
try:
	from pam import pam
	from pam.__internals import PamMessage, PamResponse, PAM_AUTH_ERR
except ImportError as e:
	syslog.syslog(syslog.LOG_ERR, f"PAM Import Error: {str(e)}")
	raise

# Setup API_URL
API_URL = None
try:
	from pam_rest_auth_conf import API_URL
except ImportError:
	pass

def signal_handler(signal, frame):
	print('User cancelled authentication.')
	sys.exit(PAM_AUTH_ERR)

signal.signal(signal.SIGINT, signal_handler)

class PamHandleProtocol(Protocol):
	"""Protocol defining the PAM handle interface"""
	PAM_SUCCESS: int
	PAM_AUTH_ERR: int
	PAM_SYSTEM_ERR: int
	PAM_USER_UNKNOWN: int
	PAM_AUTHTOK_ERR: int
	PAM_PROMPT_ECHO_ON: int
	PAM_PROMPT_ECHO_OFF: int
	exception: Any
	Message: PamMessage
	
	def get_user(self) -> Optional[str]: ...
	def get_authtok(self) -> Optional[str]: ...
	def conversation(self, messages: PamMessage | list[PamMessage]) -> PamResponse | list[PamResponse]: ...

PamHandle = PamHandleProtocol

class RESTAuthPAM:
	def __init__(self, pamh = None, debug: bool = False):
		self.pam = pam()
		self.pamh: PamHandle | None = pamh
		self.debug: bool = debug
		self.service: str = "login"
		# Max TOTP attempts
		self.totp_retries = 3

	def log(self, message: str, username: str = None) -> None:
		full_msg = f"PAM-REST: {message}"
		if username:
			full_msg = f"PAM-REST [{username}]: {message}"
		syslog.syslog(syslog.LOG_INFO, full_msg)
		if self.debug:
			print(full_msg)  # For console debugging

	def authenticate(self, username: str, password: str) -> bool:
		"""Authenticate against REST API with proper type hints"""
		try:
			if not API_URL:
				return False
			if not password:
				return False
			payload = {
				"username": username,
				"password": password
			}
			headers = {
				"Content-Type": "application/json",
				"Accept": "application/json"
			}
			
			self.log("Attempting authentication", username)
			response = requests.post(
				API_URL,
				json=payload,
				headers=headers,
				timeout=5
			)

			if response.status_code == 200:
				self.log("Successful authentication", username)
				self._ensure_local_user_exists(username)
				return True
			elif response.status_code == 428:
				return self._handle_totp_flow(username, password)

			self.log(
				f"Failed authentication (Status: {response.status_code})",
				username
			)
			return False
			
		except requests.exceptions.RequestException as e:
			self.log(f"API request failed: {str(e)}")
			return False
		except json.JSONDecodeError as e:
			self.log(f"Invalid API response: {str(e)}")
			return False
		except Exception as e:
			self.log(f"Unexpected error during authentication: {str(e)}")
			return False

	def _ensure_local_user_exists(self, username: str) -> bool:
		"""
		Creates a minimal local user if it doesn't exist.
		Returns True if user exists or was created successfully.
		"""
		try:
			# Check if user exists
			subprocess.run(
				["id", username],
				check=True,
				stdout=subprocess.DEVNULL,
				stderr=subprocess.DEVNULL
			)
			self.log(f"User {username} already exists locally")
			return True

		except subprocess.CalledProcessError:
			# User doesn't exist → create it
			try:
				self.log(f"Creating local user: {username}")
				subprocess.run([
					"sudo", "useradd",
					"-r",              # System user (no home dir)
					"-s", "/bin/false", # No shell access
					username
				], check=True)
				return True

			except subprocess.CalledProcessError as e:
				self.log(f"Failed to create user {username}: {str(e)}")
				return False

	def _handle_totp_flow(self, username: str, password: str) -> bool:
		"""Handle TOTP authentication flow"""
		for attempt in range(self.totp_retries):
			try:
				# Get TOTP from user via PAM conversation
				totp = self._get_totp_from_user()

				# Verify TOTP with API
				response = requests.post(
					API_URL,
					json={
						"username": username,
						"password": password,
						"totp_code": totp
					},
					timeout=5
				)
				
				if response.status_code == 200:
					self._ensure_local_user_exists(username)
					return True
				
				self.log(f"TOTP attempt {attempt + 1} failed")
				
			except Exception as e:
				self.log(f"TOTP error: {str(e)}")
		
		return False

	def _get_totp_from_user(self) -> str:
		"""TOTP prompt handling"""
		prompt = "Please enter your 2FA code: "

		if not hasattr(self, 'pamh') or not self.pamh:
			return input(prompt)  # Fallback for testing

		try:
			# Try conversation() first
			try:
				msg = self.pamh.Message(prompt, self.pamh.PAM_PROMPT_ECHO_ON)
			except TypeError:
				msg = self.pamh.Message(self.pamh.PAM_PROMPT_ECHO_ON, prompt)
			resp = self.pamh.conversation([msg])
			if resp and resp[0].resp:
				return resp[0].resp

			# Fallback to console if conversation() fails
			self.log("PAM conversation failed, falling back to console")
			return input(prompt)
		except Exception as e:
			self.log(f"TOTP prompt failed: {str(e)}")
			return ""

def pam_sm_authenticate(pamh: PamHandleProtocol, flags: int, argv: list[str]) -> int:
	try:
		# Get and validate username first
		username = pamh.get_user(None)
		if not username:
			return pamh.PAM_USER_UNKNOWN
			
		# Log authentication attempt with user
		syslog.syslog(syslog.LOG_INFO,
					 f"PAM-REST: Authentication attempt for {username}")
		
		# Get password
		password = None
		prompt = "Interlock IdP Password: "
		try:
			msg = pamh.Message(prompt, pamh.PAM_PROMPT_ECHO_OFF)
		except TypeError:
			msg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, prompt)
		resp = pamh.conversation([msg])
		if resp and resp[0].resp:
			password = resp[0].resp

		if not password:
			syslog.syslog(syslog.LOG_WARNING,
						f"PAM-REST: No password for {username}")
			return pamh.PAM_AUTH_ERR
		# Initialize authenticator with PAM handle
		authenticator = RESTAuthPAM(pamh=pamh)

		if not authenticator.authenticate(username, password):
			syslog.syslog(syslog.LOG_WARNING,
						f"PAM-REST: Auth failed for {username}")
			return pamh.PAM_AUTH_ERR

		syslog.syslog(syslog.LOG_INFO,
						f"PAM-REST: Auth success for {username}")
		return pamh.PAM_SUCCESS
		
	except Exception as e:
		syslog.syslog(syslog.LOG_ERR,
			"PAM-REST: System error for %s: %s\n%s",
			username,
			str(e),
			traceback.print_exc(),
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
