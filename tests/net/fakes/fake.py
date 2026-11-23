#!/usr/bin/python3
"""Test doubles for the net-lane tools: headscale, nft, tailscale, systemctl,
systemd-run, conntrack, loginctl, journalctl (dispatch on argv[0]).

State lives in $FAKE_STATE/state.json; every call is appended to calls.jsonl.
The fake `tailscale debug netmap` derives PacketFilterRules from the policy
that the fake headscale last loaded (on `systemctl reload headscale.service`),
so legatto-policy assert sees the effect of what was installed.
"""

import fcntl
import json
import os
import re
import sys

STATE_DIR = os.environ["FAKE_STATE"]
STATE = os.path.join(STATE_DIR, "state.json")
ROOT = os.environ.get("LEGATTO_TEST_ROOT", "")


class State:
    def __enter__(self):
        self.lock = open(STATE + ".lock", "w")
        fcntl.flock(self.lock, fcntl.LOCK_EX)
        try:
            with open(STATE) as fh:
                self.data = json.load(fh)
        except FileNotFoundError:
            self.data = {}
        return self.data

    def __exit__(self, *exc):
        with open(STATE + ".tmp", "w") as fh:
            json.dump(self.data, fh, indent=1, sort_keys=True)
        os.rename(STATE + ".tmp", STATE)
        fcntl.flock(self.lock, fcntl.LOCK_UN)
        self.lock.close()


def record(name, argv, stdin=None):
    with open(os.path.join(STATE_DIR, "calls.jsonl"), "a") as fh:
        fh.write(json.dumps({"cmd": name, "argv": argv, "stdin": stdin}) + "\n")


def hujson(text):
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return json.loads(text)


# --- headscale ------------------------------------------------------------------------

def headscale(argv):
    with State() as st:
        st.setdefault("users", [])
        st.setdefault("nodes", [])
        st.setdefault("next_user_id", 1 + max([u["id"] for u in st["users"]] or [0]))
        if st.get("headscale_down"):
            print("Error: connection refused", file=sys.stderr)
            return 1
        args = [a for a in argv if a not in ("--output", "json", "-o", "--force")]
        if args[:2] == ["nodes", "list"]:
            print(json.dumps(st["nodes"]))
            return 0
        if args[:2] == ["users", "list"]:
            print(json.dumps([{"id": str(u["id"]), "name": u["name"]} for u in st["users"]]))
            return 0
        if args[:2] == ["users", "create"]:
            st["users"].append({"id": st["next_user_id"], "name": args[2]})
            st["next_user_id"] += 1
            return 0
        if args[:2] == ["users", "destroy"]:
            name = args[args.index("--name") + 1]
            if any(n["user"]["name"] == name for n in st["nodes"]):
                print("Error: user has nodes", file=sys.stderr)
                return 1
            st["users"] = [u for u in st["users"] if u["name"] != name]
            return 0
        if args[:2] == ["nodes", "delete"]:
            ident = args[args.index("--identifier") + 1]
            st["nodes"] = [n for n in st["nodes"] if str(n["id"]) != ident]
            return 0
        if args[:2] == ["preauthkeys", "create"]:
            st["keys_issued"] = st.get("keys_issued", 0) + 1
            print(json.dumps({"key": f"fakekey{st['keys_issued']:04d}", "expiration": {"seconds": 4102444800}}))
            return 0
        if args[:2] == ["policy", "check"]:
            path = args[args.index("--file") + 1]
            try:
                hujson(open(path).read())
            except ValueError as exc:
                print(f"invalid policy: {exc}", file=sys.stderr)
                return 1
            if st.get("policy_check_fail"):
                print("policy rejected (fake)", file=sys.stderr)
                return 1
            return 0
    print(f"fake headscale: unsupported {argv}", file=sys.stderr)
    return 2


# --- nft ---------------------------------------------------------------------------------

ELEM_RE = re.compile(r"add element inet legatto (\S+) \{ (.*) \}")


def nft(argv, stdin):
    with State() as st:
        sets = st.setdefault("sets", {"vendor4": {}, "vendor6": {}, "bg4": {}, "bg6": {}})
        if st.get("nft_fail"):
            print("Error: netlink (fake)", file=sys.stderr)
            return 1
        if argv[:2] == ["-c", "-f"]:
            return 1 if st.get("nft_check_fail") else 0
        if argv[:2] == ["-f", "-"]:
            for line in stdin.splitlines():
                line = line.strip()
                if line.startswith("flush set inet legatto "):
                    sets[line.split()[-1]] = {}
                elif line.startswith("add element"):
                    m = ELEM_RE.match(line)
                    for item in m.group(2).split(","):
                        parts = item.split()
                        timeout = int(parts[2].rstrip("s")) if len(parts) > 2 else None
                        sets[m.group(1)][parts[0]] = timeout
            return 0
        if argv[:1] == ["-f"]:
            st["loaded"] = open(argv[1]).read()
            st["loads"] = st.get("loads", 0) + 1
            for name in sets:
                sets[name] = {}
            return 0
        if argv[:3] == ["-j", "list", "set"]:
            name = argv[-1]
            elems = [({"elem": {"val": k, "timeout": v, "expires": v}} if v else k) for k, v in sets[name].items()]
            print(json.dumps({"nftables": [{"metainfo": {}}, {"set": {"name": name, "elem": elems}}]}))
            return 0
        if argv[:2] == ["list", "table"]:
            if "loaded" not in st:
                print("Error: No such file or directory", file=sys.stderr)
                return 1
            print(st["loaded"])
            return 0
    print(f"fake nft: unsupported {argv}", file=sys.stderr)
    return 2


# --- tailscale -------------------------------------------------------------------------------

def netmap_rules(st):
    if "netmap_override" in st:  # exact PacketFilterRules as a real server reports them
        return st["netmap_override"]
    if st.get("netmap_broken") or "loaded_policy" not in st:
        return []
    policy = hujson(st["loaded_policy"])
    users = {}
    tags = {}
    for node in st.get("nodes", []):
        ips = node["ip_addresses"]
        for tag in node.get("tags", []):
            tags.setdefault(tag, []).extend(ips)
        if not node.get("tags"):
            users.setdefault(node["user"]["name"], []).extend(ips)
    rules = []
    for grant in policy.get("grants", []):
        srcs = []
        for src in grant["src"]:
            if src.startswith("group:"):
                for member in policy["groups"].get(src, []):
                    srcs.extend(users.get(member.rstrip("@"), []))
            elif src.startswith("tag:"):
                srcs.extend(tags.get(src, []))
        if not srcs:
            continue
        dsts = []
        for dst in grant["dst"]:
            for spec in grant["ip"]:
                port = int(spec.split(":")[1])
                dsts.append({"IP": policy["hosts"][dst], "Ports": {"First": port, "Last": port}})
        rules.append({"SrcIPs": srcs, "DstPorts": dsts})
    return rules


def tailscale(argv):
    with State() as st:
        if argv[:2] == ["debug", "netmap"]:
            print(json.dumps({"PacketFilterRules": netmap_rules(st)}))
            return 0
        if argv[:2] == ["whois", "--json"]:
            print(json.dumps({"Node": {"ComputedName": "fake-node"}}))
            return 0
    return 2


# --- systemd and friends -----------------------------------------------------------------------

def systemctl(argv):
    with State() as st:
        if argv == ["reload", "headscale.service"]:
            st["loaded_policy"] = open(ROOT + "/etc/headscale/policy.hujson").read()
            st["reloads"] = st.get("reloads", 0) + 1
    return 0


def loginctl(argv):
    with State() as st:
        sessions = st.setdefault("sessions", [])
        if argv[:1] == ["list-users"]:
            for index, user in enumerate(sessions):
                print(f"{1000 + index} {user}")
            return 0
        if argv[:1] == ["terminate-user"]:
            st["sessions"] = [u for u in sessions if u != argv[1]]
            st.setdefault("terminated", []).append(argv[1])
            return 0
    return 0


def conntrack(argv):
    with State() as st:
        st.setdefault("conntrack", []).append(argv)
    print("conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.", file=sys.stderr)
    return 1


def journalctl(argv):
    with State() as st:
        for line in st.get("journal", []):
            print(json.dumps(line))
        st["journal"] = []
    return 0


def main():
    name = os.path.basename(sys.argv[0])
    argv = sys.argv[1:]
    stdin = sys.stdin.read() if name == "nft" and argv[:2] == ["-f", "-"] else None
    record(name, argv, stdin)
    handlers = {"headscale": headscale, "tailscale": tailscale, "systemctl": systemctl, "loginctl": loginctl,
                "conntrack": conntrack, "journalctl": journalctl, "systemd-run": lambda a: 0}
    if name == "nft":
        return nft(argv, stdin)
    return handlers[name](argv)


if __name__ == "__main__":
    sys.exit(main())
