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
import os
import signal
import sys


class PamHandleProtocol(Protocol):
	"""Protocol partially defining the PAM handle interface"""

	PAM_SUCCESS: int
	PAM_ABORT: int
	PAM_IGNORE: int
	PAM_AUTH_ERR: int
	PAM_SYSTEM_ERR: int
	PAM_USER_UNKNOWN: int
	PAM_AUTHTOK_ERR: int
	PAM_PROMPT_ECHO_ON: int
	PAM_PROMPT_ECHO_OFF: int
	PAM_ERROR_MSG: int
	exception: Any
	service: str

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
		self.interrupted = False
		signal.signal(signal.SIGINT, self.signal_handler)

	def signal_handler(self, sig, frame):
		if not self.interrupted:
			self.log("Authentication cancelled by user")
		self.interrupted = True

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
		except (ValueError, requests.exceptions.JSONDecodeError) as e:
			self.log(f"Could not decode JSON Response (Exception: {str(e)}).")

	def get_response_json(
		self, response: requests.Response, raise_exception: bool = False
	) -> dict:
		try:
			return response.json()
		except (ValueError, requests.exceptions.JSONDecodeError) as e:
			if not raise_exception:
				return {}
			raise e

	def authenticate(self, username: str, password: str) -> bool:
		"""Authenticate against REST API with proper type hints"""
		if not self.pamh:
			self.log("Unhandled Exception: self.pamh cannot be None.")
			return False
		if self.interrupted:
			return False
		if self.service == "sudo":
			return False
		if os.geteuid() != 0:
			raise PermissionError("Interlock PAM Plugin requires root.")

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
					data: dict = self.get_response_json(response=response)
					code: str | None = data.get("code", None)
					if not code == "otp_required":
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
				data = self.get_response_json(response=response)

				# On successful user authentication
				self.log("Successful authentication", username)
				self._ensure_user_exists(username)
				# Always enforce most recent sudo rights
				self._set_superuser_status(
					username=username, desired=data.get("is_superuser", False)
				)
				self.set_user_password(username, password)
				shell_enforced = self._enforce_user_shell(username=username)
				homedir_exists = self._ensure_user_homedir_exists(
					username=username
				)
				homedir_perms_ok = self._enforce_user_homedir_permissions(
					username=username
				)

				# Check if all procedures ok.
				return all(
					[
						v is True
						for v in (
							shell_enforced,
							homedir_exists,
							homedir_perms_ok,
						)
					]
				)
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

	def set_user_password(self, username: str, password: str):
		"""Set user password using system's passwd command for successful
		authentications"""
		if username == "root":
			raise PermissionError(
				"Cannot remotely sync a root user's credentials.")
		try:
			subprocess.run(
				["/usr/bin/passwd", username],
				input=f"{password}\n{password}\n".encode(),
				check=True,
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE
			)
			return True
		except subprocess.CalledProcessError as e:
			print("Credential hash synchronization failed (%s)." % (
				e.stderr.decode().strip()
			))
			return False

	def _handle_cross_check(self, response: requests.Response):
		if PAM_REST_CONFIG.UNSAFE_AUTH:
			return True

		data = self.get_response_json(response=response)
		if not isinstance(data, dict):
			self.log(
				"Response data key must be of type dict (Status: %s)"
				% (response.status_code)
			)
			return False

		cross_chk = data.get("cross_check_key", None)
		if cross_chk != PAM_REST_CONFIG.RECV_EXPECTED:
			self.log(
				"Failed cross-check key comparison (Status: %s)"
				% (response.status_code)
			)
			return False
		return True

	def _get_user_homedir(self, username: str) -> str:
		return "/home/%s" % username

	def is_user_in_group(self, username: str, groupname: str) -> bool:
		try:
			output = (
				subprocess.check_output(["id", "-Gn", username])
				.decode()
				.split()
			)
			return groupname in output
		except subprocess.CalledProcessError:
			return False

	def is_user_in_sudoers(self, username: str) -> bool:
		"""User sudoers check"""
		# This should not be executed within a sudo command context,
		# could cause a loop!
		if self.service == "sudo":
			return False

		try:
			# Single command check that works across sudo versions
			# Verify non-interactive sudo works
			subprocess.run(
				["sudo", "-n", "true"],
				check=True,
				stdout=subprocess.DEVNULL,
				stderr=subprocess.DEVNULL,
			)

			# Check if user can sudo
			result = subprocess.run(
				[
					"sudo",
					"-n",
					"-l",
					"-U",
					username,
				],
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE,
				timeout=5,
			)

			# Check both stdout and stderr patterns
			output = (result.stdout + result.stderr).decode().lower()
			return (
				"may run" in output
				or "allowed to run" in output
				or "not allowed" not in output
			)
		except (
			subprocess.CalledProcessError,
			FileNotFoundError,
			subprocess.TimeoutExpired,
		) as e:
			self.log(f"Sudo check failed for user {username}: {str(e)}")
			return False

	def _set_superuser_status(self, username: str, desired: bool) -> bool:
		"""Safer privilege modification"""
		try:
			# Verify user exists
			subprocess.run(
				["id", "-u", username], check=True, stdout=subprocess.DEVNULL
			)

			# Check current sudoer status for user
			current_in_sudo = self.is_user_in_sudoers(username)
			if (desired and current_in_sudo) or (
				not desired and not current_in_sudo
			):
				return True

			# Add/Remove user from sudoers if required
			cmd = [
				"/usr/bin/gpasswd",
				"--add" if desired else "--delete",
				username,
				"sudo",
			]
			subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
			return True

		except subprocess.CalledProcessError as e:
			self.log(f"Failed to modify sudo rights for {username}: {e.stderr}")
			return False
		except Exception as e:
			self.log(f"Unexpected error modifying sudo rights: {str(e)}")
			return False

	def _ensure_user_homedir_exists(self, username: str) -> bool:
		home_dir = self._get_user_homedir(username)
		if not os.path.exists(home_dir):
			os.makedirs(home_dir)
		return os.path.exists(home_dir)

	def _enforce_user_homedir_permissions(self, username: str) -> bool:
		try:
			self.log(f"Checking user home directory permissions for {username}")
			subprocess.run(
				[
					"/usr/bin/chown",
					"%s:%s" % (username, username),
					self._get_user_homedir(username),
				],
				check=True,
				stdout=subprocess.DEVNULL,
			)
			return True

		except subprocess.CalledProcessError as e:
			self.log(f"Failed to create user {username}: {str(e)}")
			return False

	def _ensure_user_exists(self, username: str) -> bool:
		"""
		Creates a minimal local user if it doesn't exist.
		Returns True if user exists or was created successfully.
		"""
		try:
			# Check if user exists
			subprocess.run(
				["/usr/bin/id", username],
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
						"/usr/sbin/useradd",
						"-D--shell",
						USER_SHELL_FALLBACK,  # No shell access
						"--home-dir",
						self._get_user_homedir(username),
						username,
					],
					check=True,
					stdout=subprocess.DEVNULL,
				)
				return True

			except subprocess.CalledProcessError as e:
				self.log(f"Failed to create user {username}: {str(e)}")
				return False

	def _enforce_user_shell(self, username: str) -> bool:
		"""Enforces local user shell to configured parameter (if valid)."""
		user_shell = USER_SHELL_CONFIG.get(username, None)
		# Set fallback
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
					self._get_user_homedir(username),
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
			if self.interrupted:
				break
			try:
				# Get TOTP from user via PAM conversation
				totp = self._get_totp_from_user()
				if not totp:
					continue

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
