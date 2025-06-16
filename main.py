import configparser
import os
import re
from datetime import datetime, timedelta
from typing import MutableMapping, Union

import requests
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Config(metaclass=Singleton):
    def __init__(self):
        self._config_path = os.environ["CONFIG_PATH"]

        config = configparser.ConfigParser()
        config.read(self._config_path)
        self._config = config

    def get_section(self, section: str):
        if not section in self._config.sections():
            self._config.add_section(section)

        return self._config[section]

    def save_section(self, section: str, data: Union[dict, MutableMapping]):
        config_section = self.get_section(section)
        for key, value in data.items():
            config_section[key] = value

        with open(self._config_path, "w") as configfile:
            self._config.write(configfile)


def get_public_ips(endpoints: list) -> set:
    def ip_map(ip: str) -> str:
        match = re.match(
            r"(((?:\d{1,3}\.){3}\d{1,3})|\[((?:[0-9A-Fa-f]{0,4}:){4})"
            r"(?:[0-9A-Fa-f]{0,4}:){0,3}(?:[0-9A-Fa-f]{0,4})?\])(?::\d+)?",
            ip,
        )
        if not match:
            raise RuntimeError("Invalid IP passed for endpoint: ", ip)

        stripped_ip = (
            f"{match.group(3)}:/64" if match.group(3) else f"{match.group(2)}/32"
        )
        return stripped_ip

    cleaned_ips = set(map(ip_map, endpoints))
    public_ips = set(
        filter(
            lambda ip: not re.match(
                r"(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)"
                r"|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^::1$)|(^[fF][cCdD])",
                ip,
            ),
            cleaned_ips,
        )
    )
    return public_ips


def main():
    config = Config()
    config_data = config.get_section("MAIN")
    approved_devices = config_data["approved_devices"].split(", ")
    print("Approved devices:", config_data["approved_devices"])
    allowed_ips = set(config_data["allowed_ips"].split(", "))
    print("Allowed IPs:", ", ".join(sorted(allowed_ips)))

    ts_token = config_data["ts_token"]
    ts_expires_at = config_data["ts_expires_at"] and datetime.fromtimestamp(
        float(config_data["ts_expires_at"])
    )
    if not ts_expires_at or (ts_expires_at - timedelta(minutes=5)) < datetime.now():
        print("Tailscale token expired, refreshing...")
        ts_client_id = config_data["ts_client_id"]
        ts_client_secret = config_data["ts_client_secret"]
        client = BackendApplicationClient(client_id=ts_client_id)
        oauth = OAuth2Session(client=client)
        token_data = oauth.fetch_token(
            token_url="https://api.tailscale.com/api/v2/oauth/token",
            client_id=ts_client_id,
            client_secret=ts_client_secret,
        )
        ts_token = token_data["access_token"]
        ts_expires_at = token_data["expires_at"]
        config.save_section(
            "MAIN", {"ts_token": ts_token, "ts_expires_at": str(ts_expires_at)}
        )
        print("Tailscale token refreshed!")

    ts_session = requests.Session()
    ts_session.headers.update({"Authorization": "Bearer " + ts_token})
    devices_req = ts_session.get(
        "https://api.tailscale.com/api/v2/tailnet/-/devices?fields=all"
    )
    devices_req.raise_for_status()

    def device_map(device: dict):
        key = (
            device["hostname"]
            if not device["hostname"] == "localhost"
            else device["name"].split(".")[0]
        )
        return key.lower(), device

    devices = dict(map(device_map, devices_req.json()["devices"]))
    approved_devices_data = {k: v for k, v in devices.items() if k in approved_devices}
    device_ips = {
        k: get_public_ips(v["clientConnectivity"]["endpoints"])
        for k, v in approved_devices_data.items()
    }
    approved_device_ips = set()
    for device_name, device_ips in device_ips.items():
        print(device_name, "IPs:", ", ".join(sorted(device_ips)))
        if device_ips.difference(allowed_ips):
            print(f"WARNING: {device_name} IPs are not in allowed IPs!")
        approved_device_ips.update(device_ips)

    if not allowed_ips ^ approved_device_ips:
        print("IPs match, exiting...")
        return

    allowed_ips: set = approved_device_ips
    print("New IPs:", ", ".join(allowed_ips))
    config.save_section("MAIN", {"allowed_ips": ", ".join(allowed_ips)})
    cf_session = requests.Session()
    cf_session.headers.update({"Authorization": "Bearer " + config_data["cf_token"]})
    policies_req = cf_session.get(
        f"https://api.cloudflare.com/client/v4/accounts/{config_data["cf_account_id"]}/access/policies"
    )
    policies_req.raise_for_status()
    policy = next(
        (
            p
            for p in policies_req.json()["result"]
            if p["name"].lower() == config_data["policy_name"].lower()
        ),
        None,
    )
    if not policy:
        raise RuntimeError("Cloudflare Access Policy not found!")

    payload = {
        "decision": "bypass",
        "name": policy["name"],
        "include": [{"ip": {"ip": ip}} for ip in allowed_ips],
    }
    policy_put_req = cf_session.put(
        f"https://api.cloudflare.com/client/v4/accounts/"
        f"{config_data["cf_account_id"]}/access/policies/{policy["id"]}",
        json=payload,
    )
    policy_put_req.raise_for_status()
    print("Policy successfully updated!")


if __name__ == "__main__":
    main()
