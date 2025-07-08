import json
import requests
import syslog
import subprocess
from typing import Protocol, overload, Any, Optional
from pam import pam
from pam.__internals import PamMessage, PamResponse
from pam_rest_config import (
	PAM_REST_CONFIG,
	DEFAULT_HEADERS,
)

def handle_pam_conv_response(resp):
	if resp:
		if isinstance(resp, list):
			if hasattr(resp[0], "resp"):
				return resp[0].resp
		elif hasattr(resp, "resp"):
			return resp.resp
	return None

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
		self.totp_retries = 3

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

			if response.status_code == 200:
				if not self._handle_cross_check(response=response):
					return False
				self.log("Successful authentication", username)
				self._ensure_local_user_exists(username)
				return True
			elif response.status_code == 428:
				return self._handle_totp_flow(username, password)
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
		except json.JSONDecodeError as e:
			self.log(f"Invalid API response: {str(e)}")
			return False
		except Exception as e:
			self.log(f"Unexpected error during authentication: {str(e)}")
			return False

	def _handle_cross_check(self, response: requests.Response):
		try:
			data = response.json()
			if not isinstance(data, dict):
				self.log(
					f"Response data key must be of type dict (Status: {response.status_code})"
				)
				return False
			if not PAM_REST_CONFIG.UNSAFE_AUTH:
				if data.get("cross_check_key") != PAM_REST_CONFIG.RECV_EXPECTED:
					self.log(
						f"Failed cross-check key comparison (Status: {response.status_code})"
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
						"useradd",
						"-r",  # System user (no home dir)
						"-s",
						"/bin/false",  # No shell access
						username,
					],
					check=True,
				)
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

				if response.status_code == 200:
					if not self._handle_cross_check(response=response):
						return False
					self._ensure_local_user_exists(username)
					return True
				else:
					self.log_json_response(response=response)

				self.log(f"TOTP attempt {attempt + 1} failed")

			except Exception as e:
				self.log(f"TOTP error: {str(e)}")

		return False

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
			resp = handle_pam_conv_response(self.pamh.conversation([msg]))
			if resp:
				return resp

			# Fallback to console if conversation() fails
			self.log("PAM conversation failed, falling back to console")
			return input(prompt)
		except Exception as e:
			self.log(f"TOTP prompt failed: {str(e)}")
			return ""
