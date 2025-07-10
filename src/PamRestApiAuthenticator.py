import requests
import syslog
import subprocess
from typing import Protocol, overload, Any, Optional
from pam import pam
from pam.__internals import PamMessage, PamResponse
from constants import USER_SHELL_OPTS, USER_SHELL_FALLBACK
from pam_rest_config import (
	PAM_REST_CONFIG,
	USER_SHELL_CONFIG,
	DEFAULT_HEADERS,
)
import signal
import sys


class PamHandleProtocol(Protocol):
	"""Protocol partially defining the PAM handle interface"""

	PAM_SUCCESS: int
	PAM_ABORT: int
	PAM_AUTH_ERR: int
	PAM_SYSTEM_ERR: int
	PAM_USER_UNKNOWN: int
	PAM_AUTHTOK_ERR: int
	PAM_PROMPT_ECHO_ON: int
	PAM_PROMPT_ECHO_OFF: int
	exception: Any

	@overload
	def Message(self, msg_style: int, msg: str): ...
	@overload
	def Message(self, msg: str, msg_style: int): ...
	def get_user(self, prompt) -> Optional[str]: ...
	def get_authtok(self) -> Optional[str]: ...
	def conversation(
		self, messages: PamMessage | list[PamMessage]
	) -> PamResponse | list[PamResponse]: ...


class PamRestApiAuthenticator:
	def __init__(self, pamh=None, debug: bool = False):
		self.pam = pam()
		self.pamh: PamHandleProtocol | None = pamh
		self.debug: bool = debug
		self.service: str = "login"
		# Max TOTP attempts
		self.totp_retries = PAM_REST_CONFIG.TOTP_RETRY_LIMIT
		signal.signal(signal.SIGINT, self.signal_handler)

	def signal_handler(self, sig, frame):
		self.log("Authentication cancelled by user")
		if self.pamh:
			sys.exit(self.pamh.PAM_ABORT)
		sys.exit(1)

	def log(self, message: str, username: str | None = None) -> None:
		full_msg = f"PAM-REST: {message}"
		if username:
			full_msg = f"PAM-REST [{username}]: {message}"
		syslog.syslog(syslog.LOG_INFO, full_msg)
		if self.debug:
			print(full_msg)  # For console debugging

	def log_json_response(self, response: requests.Response):
		try:
			json_resp = response.json()
			self.log(str(json_resp))
		except ValueError:
			self.log("Could not decode JSON Response.")

	def authenticate(self, username: str, password: str) -> bool:
		"""Authenticate against REST API with proper type hints"""
		try:
			if not PAM_REST_CONFIG.API_URL:
				self.log("Improperly Configured: API_URL is required.")
				return False
			if not password:
				self.log("No password provided, ignoring.")
				return False
			payload = {
				"username": username,
				"password": password,
				"unsafe": True if PAM_REST_CONFIG.UNSAFE_AUTH else False,
				"cross_check_key": PAM_REST_CONFIG.SEND_ENCRYPTED,
			}

			self.log("Attempting authentication", username)
			response = requests.post(
				PAM_REST_CONFIG.API_URL,
				json=payload,
				headers=DEFAULT_HEADERS,
				timeout=5,
			)
			# TOTP Code Required Case Handling
			if response.status_code == 428:  # Precondition Required
				try:
					data: dict = response.json()
					code: str | None = data.get("code", None)
					if not code == "otp_required":
						return False
				except ValueError:
					return False
				except Exception as e:
					self.log(
						"Unhandled Exception parsing response json (%s)."
						% (str(e)),
						username,
					)

				response = self._handle_totp_flow(username, password)
				if not response:
					return False

			# Handle final response
			if response.status_code == 200:  # OK
				if not self._handle_cross_check(response=response):
					return False
				self.log("Successful authentication", username)
				self._ensure_local_user_exists(username)
				self._enforce_local_user_shell(username)
				return True
			else:
				self.log_json_response(response=response)

			self.log(
				f"Failed authentication (Status: {response.status_code})",
				username,
			)
			return False

		except requests.exceptions.RequestException as e:
			self.log(f"API request failed: {str(e)}")
			return False
		except ValueError as e:
			self.log(f"Invalid API response: {str(e)}")
			return False
		except Exception as e:
			self.log(f"Unexpected error during authentication: {str(e)}")
			return False

	def _handle_cross_check(self, response: requests.Response):
		if PAM_REST_CONFIG.UNSAFE_AUTH:
			return True
		try:
			data = response.json()
			if not isinstance(data, dict):
				self.log(
					"Response data key must be of type dict (Status: %s)" % (
						response.status_code
					)
				)
				return False

			cross_chk = data.get("cross_check_key", None)
			if cross_chk != PAM_REST_CONFIG.RECV_EXPECTED:
				self.log(
					"Failed cross-check key comparison (Status: %s)" % (
						response.status_code
					)
				)
				return False
		except requests.exceptions.JSONDecodeError:
			self.log(
				f"Failed to decode response (Status: {response.status_code})"
			)
			return False
		return True

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
				stderr=subprocess.DEVNULL,
			)
			self.log(f"User {username} already exists locally")
			return True

		except subprocess.CalledProcessError:
			# User doesn't exist → create it
			try:
				self.log(f"Creating local user: {username}")
				subprocess.run(
					[
						"sudo",
						"/usr/sbin/useradd",
						"--shell",
						USER_SHELL_FALLBACK,  # No shell access
						"--home-dir",
						"/home/%s" % username,
						username,
					],
					check=True,
					stdout=subprocess.DEVNULL,
				)
				return True

			except subprocess.CalledProcessError as e:
				self.log(f"Failed to create user {username}: {str(e)}")
				return False

	def _enforce_local_user_shell(self, username: str) -> bool:
		"""Enforces local user shell to configured parameter (if valid)."""
		user_shell = USER_SHELL_CONFIG.get(username, None)
		if user_shell not in USER_SHELL_OPTS or not user_shell:
			self.log(
				"Invalid shell for user %s, reverting to %s"
				% (
					username,
					USER_SHELL_FALLBACK,
				)
			)
			user_shell = USER_SHELL_FALLBACK

		try:
			self.log(f"Enforcing user homedir and shell for {username}")
			subprocess.run(
				[
					"/usr/sbin/usermod",
					"--shell",
					user_shell,  # No shell access
					"--home",
					"/home/%s" % username,
					"--move-home",
					username,
				],
				check=True,
				stdout=subprocess.DEVNULL,
			)
			return True
		except subprocess.CalledProcessError as e:
			self.log(f"Failed to enforce user shell for {username}: {str(e)}")
			return False

	def _handle_totp_flow(
		self, username: str, password: str
	) -> requests.Response | None:
		"""Handle TOTP authentication flow"""
		for attempt in range(self.totp_retries):
			try:
				# Get TOTP from user via PAM conversation
				totp = self._get_totp_from_user()

				# Verify TOTP with API
				response = requests.post(
					PAM_REST_CONFIG.API_URL,
					json={
						"username": username,
						"password": password,
						"unsafe": True
						if PAM_REST_CONFIG.UNSAFE_AUTH
						else False,
						"cross_check_key": PAM_REST_CONFIG.SEND_ENCRYPTED,
						"totp_code": int(totp.strip()),
					},
					headers=DEFAULT_HEADERS,
					timeout=5,
				)

				if not response.status_code == 200:
					self.log(f"TOTP attempt {attempt + 1} failed")
					self.log_json_response(response=response)
				return response
			except Exception as e:
				self.log(f"TOTP error: {str(e)}")
		return None

	def _get_totp_from_user(self) -> str:
		"""TOTP prompt handling"""
		prompt = "Please enter your 2FA code: "

		if not hasattr(self, "pamh") or not self.pamh:
			return input(prompt)  # Fallback for testing

		try:
			# Try conversation() first
			try:
				msg = self.pamh.Message(prompt, self.pamh.PAM_PROMPT_ECHO_ON)
			except TypeError:
				msg = self.pamh.Message(self.pamh.PAM_PROMPT_ECHO_ON, prompt)
			resp = self.pamh.conversation([msg])
			if resp and hasattr(resp[0], "resp"):  # type: ignore
				return resp[0].resp  # type: ignore

			# Fallback to console if conversation() fails
			self.log("PAM conversation failed, falling back to console")
			return input(prompt)
		except Exception as e:
			self.log(f"TOTP prompt failed: {str(e)}")
			return ""
