#!/usr/bin/env python3

import os
import sys
import json
import logging
import argparse
import tempfile
import subprocess
from datetime import datetime, timedelta
from urllib.parse import urlsplit

logger = logging.getLogger("qute_1pass")

CACHE_DIR = os.path.join(tempfile.gettempdir(), "qute_1pass")
os.makedirs(CACHE_DIR, exist_ok=True)

SESSION_PATH = os.path.join(CACHE_DIR, "session")
SESSION_DURATION = timedelta(minutes=30)

LAST_ITEM_PATH = os.path.join(CACHE_DIR, "last_item")
LAST_ITEM_DURATION = timedelta(seconds=10)

OP_SUBDOMAIN = "my"
CMD_PASSWORD_PROMPT = (
    "rofi -password -dmenu -p 'Vault Password' -l 0 -sidebar -width 20"
)
CMD_ITEM_SELECT = "echo -e '{items}' | rofi -dmenu -p 'Select login'"
CMD_LIST_PROMPT = "echo {items} | rofi -dmenu"

CMD_OP_LOGIN = "echo -n {password} | op signin {subdomain} --output=raw"
CMD_OP_LIST_ITEMS = "op list items --categories Login --session={session_id}"
CMD_OP_GET_ITEM = "op get item {uuid} --session={session_id}"
CMD_OP_GET_TOTP = "op get totp {uuid} --session={session_id}"

QUTE_FIFO = os.environ["QUTE_FIFO"]

parser = argparse.ArgumentParser()
parser.add_argument(
    "command", help="fill_credentials, fill_totp, fill_username, fill_password"
)
parser.add_argument(
    "--auto-submit", help="Auto submit after filling", action="store_true"
)
parser.add_argument(
    "--cache-session",
    help="Cache 1password session for 30 minutes",
    action="store_true",
)
parser.add_argument(
    "--allow-insecure-sites",
    help="Allow filling credentials on insecure sites",
    action="store_true",
)


class Qute:
    """Logic related to qutebrowser"""

    @classmethod
    def _command(cls, command, *args):
        with open(QUTE_FIFO, "w") as fifo:
            logger.info(f"{command} {' '.join(args)}")
            fifo.write(f"{command} {' '.join(args)}\n")
            fifo.flush()

    @classmethod
    def _message(cls, message, type="error"):
        cls._command(f"message-{type}", f"'qute-1password: {message}'")

    @classmethod
    def message_error(cls, message):
        cls._message(message)

    @classmethod
    def message_warning(cls, message):
        cls._message(message, type="warning")

    @classmethod
    def fake_key(cls, key):
        key = key.replace(" ", "<Space>")
        cls._command("fake-key", key)

    @classmethod
    def fill_credentials_tabmode(cls, username, password, submit=False):
        cls.fake_key(username)
        cls.fake_key("<TAB>")
        cls.fake_key(password)
        if submit:
            cls.fake_key("<Return>")

    @classmethod
    def fill_single_field_tabmode(cls, value, submit=False):
        cls.fake_key(value)
        if submit:
            cls.fake_key("<Return>")

    @classmethod
    def fill_totp(cls, totp, submit=True):
        cls.fake_key(totp)
        if submit:
            cls.fake_key("<Return>")


class ExecuteError(Exception):
    """Used when commands executed return code is not 0"""

    pass


def execute_command(command):
    """Executes a command, mainly used to launch commands for user input and the op cli"""
    result = subprocess.run(command, shell=True, capture_output=True, encoding="utf-8")

    if result.returncode != 0:
        logger.error(result.stderr)
        raise ExecuteError(result.stderr)

    return result.stdout.strip()


def extract_host(url):
    """Extracts the host from a given URL"""
    _, host, *_ = urlsplit(url)
    return host


class OnePass:
    """Logic related to the op command and parsing results"""

    @classmethod
    def login(cls):
        try:
            password = execute_command(CMD_PASSWORD_PROMPT)
        except ExecuteError:
            Qute.message_error("Error calling pinentry program")
            sys.exit(0)

        try:
            session_id = execute_command(
                CMD_OP_LOGIN.format(password=password, subdomain=OP_SUBDOMAIN)
            )
        except ExecuteError:
            Qute.message_error("Login error")
            sys.exit(0)

        if arguments.cache_session:
            with open(SESSION_PATH, "w") as handler:
                handler.write(session_id)

        return session_id

    @classmethod
    def get_session(cls):
        """
        Returns a session for the op command to make calls with.
        If a session is cached, we check if it's expired first to avoid any errors.
        """
        if arguments.cache_session and os.path.isfile(SESSION_PATH):
            # op sessions last 30 minutes, check if still valid
            creation_time = datetime.fromtimestamp(os.stat(SESSION_PATH).st_ctime)
            if (datetime.now() - creation_time) < SESSION_DURATION:
                return open(SESSION_PATH, "r").read()
            else:
                # Session expired
                os.unlink(SESSION_PATH)

        return cls.login()

    @classmethod
    def list_items(cls):
        session_id = cls.get_session()
        result = execute_command(CMD_OP_LIST_ITEMS.format(session_id=session_id))
        parsed = json.loads(result)
        return parsed

    @classmethod
    def get_item(cls, uuid):
        session_id = cls.get_session()
        try:
            result = execute_command(
                CMD_OP_GET_ITEM.format(uuid=uuid, session_id=session_id)
            )
        except ExecuteError:
            logger.error("Error retrieving credential", exc_info=True)
        parsed = json.loads(result)

        return parsed

    @classmethod
    def get_item_for_url(cls, url):
        host = extract_host(url)

        def filter_host(item):
            """Exclude items that does not match host on any configured URL"""
            if "URLs" in item["overview"]:
                return any(filter(lambda x: host in x["u"], item["overview"]["URLs"]))
            return False

        items = cls.list_items()
        filtered = filter(filter_host, items)
        mapping = {
            f"{host}: {item['overview']['title']} ({item['uuid']})": item
            for item in filtered
        }

        if not mapping:
            raise cls.NoItemsFoundError(f"No items found for host {host}")

        try:
            credential = execute_command(
                CMD_ITEM_SELECT.format(items="\n".join(mapping.keys()))
            )
        except ExecuteError:
            pass

        if not credential:
            # Cancelled
            return

        return cls.get_item(mapping[credential]["uuid"])

    @classmethod
    def get_credentials(cls, item):
        username = password = None
        for field in item["details"]["fields"]:
            if field.get("designation") == "username":
                username = field["value"]
            if field.get("designation") == "password":
                password = field["value"]

        if username is None or password is None:
            logger.warning(
                "Present: username={username} password={password}".format(
                    username=username is not None, password=password is not None
                )
            )
            Qute.message_warning("Filled incomplete credentials")

        return {"username": username, "password": password}

    @classmethod
    def get_totp(cls, uuid):
        session_id = cls.get_session()
        try:
            return execute_command(
                CMD_OP_GET_TOTP.format(uuid=uuid, session_id=session_id)
            )
        except ExecuteError:
            logger.error("Error retrieving TOTP", exc_info=True)

    class NoItemsFoundError(Exception):
        pass


class CLI:
    def __init__(self, arguments):
        self.arguments = arguments

    def run(self):
        command = self.arguments.command
        if command != "run" and not command.startswith("_") and hasattr(self, command):
            return getattr(self, command)()

    def _get_item(self):
        try:
            item = OnePass.get_item_for_url(os.environ["QUTE_URL"])
        except OnePass.NoItemsFoundError as error:
            Qute.message_warning("No item found for this site")
            logger.error(f"No item found for site: {os.environ['QUTE_URL']}")
            logger.error(error)
            sys.exit(0)
        return item

    def _store_last_item(self, item):
        """
        Stores a reference to an item to easily get single information from it (password, TOTP)
        right after filling the username or credentials.
        """
        last_item = {"host": extract_host(os.environ["QUTE_URL"]), "uuid": item["uuid"]}
        with open(LAST_ITEM_PATH, "w") as handler:
            handler.write(json.dumps(last_item))

    def _fill_single_field(self, field):
        item = self._get_item()
        credentials = OnePass.get_credentials(item)
        Qute.fill_single_field_tabmode(
            credentials[field], submit=self.arguments.auto_submit
        )
        return item

    def fill_username(self):
        item = self._fill_single_field("username")
        self._store_last_item(item)

    def fill_password(self):
        item = self._fill_single_field("password")
        self._store_last_item(item)

    def fill_credentials(self):
        item = self._get_item()
        credentials = OnePass.get_credentials(item)
        Qute.fill_credentials_tabmode(
            *credentials.values(), submit=self.arguments.auto_submit
        )
        self._store_last_item(item)

    def fill_totp(self):
        # Check last item first
        # If theres a last_item file created in the last LAST_ITEM_DURATION seconds
        # and the host matches the one the user is visiting, use that UUID to retrieve
        # the totp
        item = None

        if os.path.isfile(LAST_ITEM_PATH):
            creation_time = datetime.fromtimestamp(os.stat(LAST_ITEM_PATH).st_ctime)
            if (datetime.now() - creation_time) < LAST_ITEM_DURATION:
                last_item = json.loads(open(LAST_ITEM_PATH, "r").read())
                if last_item["host"] == extract_host(os.environ["QUTE_URL"]):
                    item = last_item

        if not item:
            item = self._get_item()

        totp = OnePass.get_totp(item["uuid"])
        logger.error(totp)
        Qute.fill_totp(totp)

        if os.path.isfile(LAST_ITEM_PATH):
            os.unlink(LAST_ITEM_PATH)


if __name__ == "__main__":
    arguments = parser.parse_args()

    # Prevent filling credentials in non-secure sites if not explicitly allwoed
    if not arguments.allow_insecure_sites:
        if urlsplit(os.environ["QUTE_URL"])[0] != "https":
            Qute.message_error(
                "Trying to fill a non-secure site. If you want to allow it add the --allow-insecure-sites flag."
            )
            logger.error("Refusing to fill credentials on non-secure sites")
            sys.exit(0)

    cli = CLI(arguments)
    sys.exit(cli.run())
