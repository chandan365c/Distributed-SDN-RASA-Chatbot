import requests
from typing import Any, Text, Dict, List
from rasa_sdk import Action, Tracker
from rasa_sdk.executor import CollectingDispatcher
from rasa_sdk.events import SlotSet, EventType
import time
import json
import logging
import threading
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ONOS_CONTROLLERS = [
    {"ip": "localhost", "port": 8181},
    {"ip": "localhost", "port": 8182},
    {"ip": "localhost", "port": 8183},
    {"ip": "localhost", "port": 8184},
    {"ip": "localhost", "port": 8185},
]

AUTH = ("onos", "rocks")

def send_to_healthy_controller(endpoint: str, method="get", data=None, json_payload=None, device_id=None, require_mastership=False) -> Any:
    for ctrl in ONOS_CONTROLLERS:
        try:
            if require_mastership and device_id:
                master_url = f"http://{ctrl['ip']}:{ctrl['port']}/onos/v1/mastership/{device_id}"
                master_resp = requests.get(master_url, auth=AUTH, timeout=2)
                if master_resp.ok:
                    master_id = master_resp.json().get("master", {}).get("id", "")
                    if master_id and f"{ctrl['ip']}:{ctrl['port']}" not in master_id:
                        continue
                else:
                    continue
            url = f"http://{ctrl['ip']}:{ctrl['port']}{endpoint}"
            resp = requests.request(method, url, auth=AUTH, timeout=5, data=data, json=json_payload)
            if resp.ok:
                if resp.headers.get("Content-Type", "").startswith("application/json"):
                    return resp.json()
                else:
                    return {"status": "success", "message": resp.text}
        except requests.RequestException:
            time.sleep(0.1)
            continue
    return {"error": "All controllers unreachable or not master for this device"}

def extract_slot_value(tracker: Tracker, slot_name: str) -> str:
    value = tracker.get_slot(slot_name)
    return value.strip() if value else None
    
# === Action: Get Devices ===
#### Works ####
class ActionGetDevices(Action):
    def name(self) -> str:
        return "action_get_devices"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        logger.info("Getting devices from ONOS")
        result = send_to_healthy_controller("/onos/v1/devices")
        
        if "error" in result:
            dispatcher.utter_message(text="❌ Could not reach any ONOS controller to fetch devices.")
        else:
            devices = result.get("devices", [])
            if devices:
                device_list = []
                for device in devices:
                    device_id = device.get("id", "Unknown")
                    device_type = device.get("type", "Unknown")
                    available = "✅" if device.get("available", False) else "❌"
                    device_list.append(f"{available} {device_id} ({device_type})")
                
                message = f"🖧 Number of Connected Devices: ({len(devices)}):\n" + "\n".join(device_list)
                dispatcher.utter_message(text=message)
            else:
                dispatcher.utter_message(text="📭 No devices found in the network.")
        
        return []


# === Action: Add Flow ===
#### Works ####
class ActionAddFlow(Action):
    def name(self) -> Text:
        return "action_add_flow"

    def extract_slot(self, slot_name, tracker):
        value = tracker.get_slot(slot_name)
        return value.strip() if value else None

    def find_master_controller(self, device_id):
        controller_ips = ["10.0.0.21", "10.0.0.22", "10.0.0.23", "10.0.0.24", "10.0.0.25"]
        for ip in controller_ips:
            url = f"http://{ip}:8181/onos/v1/devices/{device_id}"
            try:
                response = requests.get(url, auth=('onos', 'rocks'))
                if response.status_code == 200:
                    data = response.json()
                    if data.get("role") == "MASTER":
                        return ip
            except Exception as e:
                continue
        return None

    async def run(self, dispatcher, tracker, domain):
        device_id = self.extract_slot("device_id", tracker)
        in_port = self.extract_slot("in_port", tracker)
        out_port = self.extract_slot("out_port", tracker)
        priority = self.extract_slot("priority", tracker)

        if not all([device_id, in_port, out_port, priority]):
            dispatcher.utter_message(text="⚠️ Missing values: device ID, input/output ports, or priority. Please provide all required details.")
            return []

        master_ip = self.find_master_controller(device_id)
        if not master_ip:
            dispatcher.utter_message(text=f"❌ Could not find any MASTER controller for {device_id}. Check controller status or device connection.")
            return []

        flow_payload = {
            "priority": int(priority),
            "timeout": 0,
            "isPermanent": True,
            "deviceId": device_id,
            "treatment": {
                "instructions": [{"type": "OUTPUT", "port": out_port}]
            },
            "selector": {
                "criteria": [{"type": "IN_PORT", "port": in_port}]
            }
        }

        url = f"http://{master_ip}:8181/onos/v1/flows/{device_id}"
        headers = {"Content-Type": "application/json"}
        try:
            response = requests.post(url, auth=('onos', 'rocks'), headers=headers, data=json.dumps(flow_payload))
            if response.status_code in [200, 201, 204]:
                dispatcher.utter_message(text=f"✅ Flow added successfully to {device_id} from port {in_port} to port {out_port} with priority {priority}")
            else:
                dispatcher.utter_message(text=f"❌ Failed to install flow rule on {device_id}. Status code: {response.status_code}")
        except Exception as e:
            dispatcher.utter_message(text=f"❌ Error occurred: {e}")

        return []

# === Action: Delete Flow ===
class ActionDeleteFlow(Action):
    def name(self) -> Text:
        return "action_delete_flow"

    def extract_slot(self, slot_name, tracker):
        value = tracker.get_slot(slot_name)
        return value.strip() if value else None

    async def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        device_id = self.extract_slot("device_id", tracker)
        flow_id = self.extract_slot("flow_id", tracker)

        if not all([device_id, flow_id]):
            dispatcher.utter_message(text="⚠️ Please provide both `device ID` and `flow ID` to delete the flow.")
            return []

        # 🔁 Convert hex to decimal if needed
        try:
            if flow_id.startswith("0x"):
                flow_id = str(int(flow_id, 16))
        except ValueError:
            dispatcher.utter_message(text="❌ Invalid flow ID format. Make sure it's a proper hexadecimal or decimal value.")
            return []

        # Attempt deletion from any reachable controller
        for ctrl in ONOS_CONTROLLERS:
            try:
                url = f"http://{ctrl['ip']}:{ctrl['port']}/onos/v1/flows/{device_id}/{flow_id}"
                response = requests.delete(url, auth=AUTH, timeout=5)
                if response.status_code in [200, 204]:
                    dispatcher.utter_message(text=f"✅ Flow `{flow_id}` successfully deleted from device `{device_id}`.")
                    return []
                else:
                    logger.warning(f"Controller {ctrl['ip']}:{ctrl['port']} responded with {response.status_code}")
            except Exception as e:
                logger.error(f"Failed to delete flow on {ctrl['ip']}:{ctrl['port']} - {e}")
                continue

        dispatcher.utter_message(text="❌ Failed to delete the flow. All controllers may be unreachable or not master.")
        return []

# === Action: Get Controller Status ===
#### Works ####
class ActionCheckControllers(Action):
    def name(self):
        return "action_check_controllers"

    def run(self, dispatcher, tracker, domain):
        reachable = []
        unreachable = []

        for ctrl in ONOS_CONTROLLERS:
            url = f"http://{ctrl['ip']}:{ctrl['port']}/onos/v1/cluster"
            try:
                response = requests.get(url, auth=AUTH, timeout=3)
                if response.status_code == 200:
                    reachable.append(f"{ctrl['ip']}:{ctrl['port']}")
                else:
                    unreachable.append(f"{ctrl['ip']}:{ctrl['port']}")
            except Exception:
                unreachable.append(f"{ctrl['ip']}:{ctrl['port']}")

        # Format the response
        if reachable:
            dispatcher.utter_message(text="🟢 **Reachable Controllers:**\n" + "\n".join(reachable))
        if unreachable:
            dispatcher.utter_message(text="🔴 **Unreachable Controllers:**\n" + "\n".join(unreachable))

        return []

# === Action: Default Fallback ===
#### Works ####
class ActionDefaultFallback(Action):
    def name(self) -> str:
        return "action_default_fallback"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        dispatcher.utter_message(text="🤔 Sorry, I didn't understand that. I can help you with:\n"
                                     "• Show devices, hosts, ports, flows\n"
                                     "• Add flow rules\n"
                                     "• Block/unblock hosts\n"
                                     "• Check controller status\n"
                                     "• Display network topology\n\n"
                                     "Try asking something like 'show all devices' or 'check controllers'")
        return []


# === Action: Get Hosts ===
#### Works ####
class ActionGetHosts(Action):
    def name(self) -> str:
        return "action_get_hosts"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        logger.info("Getting hosts from ONOS")
        result = send_to_healthy_controller("/onos/v1/hosts")

        if "error" in result:
            dispatcher.utter_message(text="❌ Could not fetch hosts from any controller.")
        else:
            hosts = result.get("hosts", [])
            if hosts:
                host_list = []
                for host in hosts:
                    host_id = host.get("id", "Unknown")
                    mac = host.get("mac", "Unknown")
                    ip = host.get("ipAddresses", ["Unknown"])[0] if host.get("ipAddresses") else "Unknown"
                    location_obj = host.get("location", {})
                    element_id = location_obj.get("elementId", "Unknown")
                    port = location_obj.get("port", "Unknown")

                    host_list.append(f" {host_id} (MAC: {mac}, IP: {ip})")

                message = f"🏠 Number of Network Hosts ({len(hosts)}):\n" + "\n".join(host_list)
                dispatcher.utter_message(text=message)
            else:
                dispatcher.utter_message(text="📭 No hosts found in the network.")

        return []

# === Action: Block Host ===
class ActionBlockHost(Action):
    def name(self) -> Text:
        return "action_block_host"

    def run(self, dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:

        host_id = tracker.get_slot("host_id")

        if not host_id:
            dispatcher.utter_message(text="⚠️ Please provide a valid host MAC address.")
            return []

        for controller in ONOS_CONTROLLERS:
            ip = controller["ip"]
            port = controller["port"]
            base_url = f"http://{ip}:{port}/onos/v1"
            auth = ("onos", "rocks")
            master_found = False

            try:
                # 1. Get ONOS cluster nodes
                response = requests.get(f"{base_url}/cluster/nodes", auth=auth, timeout=2)
                if response.status_code == 200:
                    nodes = response.json()
                    for node in nodes:
                        # Match using controller port in the node ID
                        if str(port) in node.get("id", "") and node.get("role") == "MASTER":
                            master_found = True
                            break

                if not master_found:
                    continue

                # 2. Get host info
                host_response = requests.get(f"{base_url}/network/hosts", auth=auth, timeout=2)
                if host_response.status_code != 200:
                    continue

                hosts = host_response.json()
                matched_host = next((h for h in hosts if h["mac"] == host_id), None)

                if not matched_host:
                    dispatcher.utter_message(text=f"❌ Host {host_id} not found.")
                    return []

                location = matched_host["locations"][0]
                device_id = location["elementId"]
                port_num = location["port"]

                flow_rule = {
                    "priority": 40000,
                    "timeout": 0,
                    "isPermanent": True,
                    "deviceId": device_id,
                    "treatment": {},
                    "selector": {
                        "criteria": [
                            {
                                "type": "ETH_DST",
                                "mac": host_id
                            }
                        ]
                    }
                }

                # 3. Push flow to block host
                flow_url = f"{base_url}/flows/{device_id}"
                flow_response = requests.post(flow_url, json=flow_rule, auth=auth, timeout=2)

                if flow_response.status_code in [200, 201, 204]:
                    dispatcher.utter_message(text=f"🚫 Host {host_id} has been blocked on {device_id}.")
                    return []

            except Exception as e:
                print(f"[ERROR] Failed for controller {ip}:{port} - {e}")
                continue

        dispatcher.utter_message(text=f"❌ Failed to block host {host_id}. All controllers unreachable or not master for this device.")
        return []

# === Action: Unblock Host ===
class ActionUnblockHost(Action):
    def name(self) -> str:
        return "action_unblock_host"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        host_id = tracker.get_slot("host_id")
        if not host_id:
            dispatcher.utter_message(text="⚠️ Please specify a host ID to unblock (e.g., 'unblock host AA:BB:CC:DD:EE:FF')")
            return []
        
        logger.info(f"Unblocking host: {host_id}")
        result = send_to_healthy_controller(f"/onos/v1/acl/allow/{host_id}", method="post")
        
        if "error" in result:
            dispatcher.utter_message(text=f"❌ Failed to unblock host {host_id}. {result.get('error', '')}")
        else:
            dispatcher.utter_message(text=f"✅ Host {host_id} has been unblocked successfully.")
        
        return []


# === Action: Get Ports ===
class ActionGetPorts(Action):
    def name(self) -> str:
        return "action_get_ports"

    def run(
        self,
        dispatcher: CollectingDispatcher,
        tracker: Tracker,
        domain: Dict[str, Any]
    ) -> List[EventType]:
        device_id = tracker.get_slot("device_id")

        user_input = tracker.latest_message.get("text", "").lower().strip()
        if not device_id or user_input in ["show ports", "get ports", "ports", "port status"]:
            dispatcher.utter_message(
                text="⚠️ Please specify a device ID.\n"
                     "Example: `show ports on device of:0000000000000001`"
            )
            return [SlotSet("device_id", None)]

        logger.info(f"Getting ports for device: {device_id}")
        result = send_to_healthy_controller(f"/onos/v1/devices/{device_id}/ports")

        if "error" in result:
            dispatcher.utter_message(text=f"❌ Failed to fetch ports for device `{device_id}`.")
            return []

        ports = result.get("ports", [])
        if ports:
            port_list = []
            for port in ports:
                port_num = port.get("port", "Unknown")
                enabled = "✅" if port.get("isEnabled", False) else "❌"
                speed = port.get("portSpeed", "Unknown")
                port_list.append(f"{enabled} Port {port_num} (Speed: {speed})")

            message = f"🔌 **Ports on `{device_id}` ({len(ports)} total):**\n" + "\n".join(port_list)
            dispatcher.utter_message(text=message)
        else:
            dispatcher.utter_message(text=f"📭 No ports found on device `{device_id}`.")

        return []

# === Action: Get Flows ===
#### Works ####
class ActionGetFlows(Action):
    def name(self) -> str:
        return "action_get_flows"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        import re
        device_id = tracker.get_slot("device_id")

        # Extract device_id from raw message text if not found in slot
        if not device_id:
            user_text = tracker.latest_message.get("text", "")
            match = re.search(r"(of:[0-9a-fA-F]+)", user_text)
            if match:
                device_id = match.group(1)

        if not device_id:
            dispatcher.utter_message(text="⚠️ Please specify a device ID \n Example: 'show flows on device of:0000000000000001'")
            return []

        logger.info(f"Getting flows for device: {device_id}")
        result = send_to_healthy_controller(f"/onos/v1/flows/{device_id}")

        if "error" in result:
            dispatcher.utter_message(text=f"❌ Failed to fetch flows for device {device_id}.")
            return []

        flows = result.get("flows", [])
        if not flows:
            dispatcher.utter_message(text=f"📭 No flows found on device {device_id}.")
            return []

        message_lines = [f"🔁 **Flows on {device_id} ({len(flows)}):**"]

        for flow in flows:
            # Convert ID to hex
            raw_id = flow.get("id", 0)
            try:
                flow_id = hex(int(raw_id)) if isinstance(raw_id, int) or raw_id.isdigit() else str(raw_id)
            except:
                flow_id = str(raw_id)

            # Extract ports
            in_port = "?"
            out_port = "?"
            for c in flow.get("selector", {}).get("criteria", []):
                if c.get("type") == "IN_PORT":
                    in_port = str(c.get("port", "?"))
            for ins in flow.get("treatment", {}).get("instructions", []):
                if ins.get("type") == "OUTPUT":
                    out_port = str(ins.get("port", "?"))

            # Priority and state
            priority = flow.get("priority", "?")
            state = flow.get("state", "?")

            message_lines.append(f"🔁 ID: {flow_id} | In: {in_port} → Out: {out_port} | Prio: {priority} | State: {state}")

        dispatcher.utter_message(text="\n".join(message_lines))
        return []

# === Action: Show Topology ===
#### Works ####
class ActionShowTopology(Action):
    def name(self) -> str:
        return "action_show_topology"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        logger.info("Fetching full topology details")

        devices_resp = send_to_healthy_controller("/onos/v1/devices")
        hosts_resp = send_to_healthy_controller("/onos/v1/hosts")
        links_resp = send_to_healthy_controller("/onos/v1/links")
        cluster_nodes_resp = send_to_healthy_controller("/onos/v1/cluster/nodes")

        device_count = len(devices_resp.get("devices", [])) if isinstance(devices_resp, dict) else 0
        host_count = len(hosts_resp.get("hosts", [])) if isinstance(hosts_resp, dict) else 0
        link_count = len(links_resp.get("links", [])) if isinstance(links_resp, dict) else 0

        if isinstance(cluster_nodes_resp, dict) and "nodes" in cluster_nodes_resp:
            nodes = cluster_nodes_resp.get("nodes", [])
            cluster_count = 1 if len(nodes) > 0 else 0
        else:
            cluster_count = 0

        message = (
            f"🌐 **Real-Time Network Topology:**\n"
            f"📱 Devices: {device_count}\n"
            f"🔗 Links: {link_count}\n"
            f"🏠 Hosts: {host_count}\n"
        )

        dispatcher.utter_message(text=message)
        return []

class ActionFindPath(Action):
    def name(self) -> str:
        return "action_find_path"

    def run(
        self,
        dispatcher: CollectingDispatcher,
        tracker: Tracker,
        domain: Dict[str, Any]
    ) -> List[EventType]:
        source_host = extract_slot_value(tracker, "source_host")
        destination_host = extract_slot_value(tracker, "destination_host")

        # Detect "find path" without any MACs or slot values
        user_input = tracker.latest_message.get("text", "").lower().strip()
        if user_input in ["find path", "show path", "path", "route", "find route"] or not all([source_host, destination_host]):
            dispatcher.utter_message(
                text="⚠️ Please provide both source and destination MAC addresses.\n"
                     "Example: `find path from 5A:4B:3C:2D:1E:0F to A1:B2:C3:D4:E5:F6`"
            )
            # Clear any leftover slots
            return [SlotSet("source_host", None), SlotSet("destination_host", None)]

        logger.info(f"Finding path from {source_host} to {destination_host}")

        # Step 1: Get all hosts
        hosts_result = send_to_healthy_controller("/onos/v1/hosts")
        if "error" in hosts_result:
            dispatcher.utter_message(text="❌ Failed to fetch host data.")
            return []

        hosts = hosts_result.get("hosts", [])
        src_host_info = next((h for h in hosts if h.get("mac", "").lower() == source_host.lower()), None)
        dst_host_info = next((h for h in hosts if h.get("mac", "").lower() == destination_host.lower()), None)

        # Step 2: Verify existence
        if not src_host_info:
            dispatcher.utter_message(text=f"❌ Source host `{source_host}` not found.")
            return [SlotSet("source_host", None)]
        if not dst_host_info:
            dispatcher.utter_message(text=f"❌ Destination host `{destination_host}` not found.")
            return [SlotSet("destination_host", None)]

        # Step 3: Get location info
        src_loc = src_host_info["locations"][0]
        dst_loc = dst_host_info["locations"][0]
        src_device = src_loc["elementId"]
        dst_device = dst_loc["elementId"]
        src_port = src_loc["port"]
        dst_port = dst_loc["port"]

        # Same switch?
        if src_device == dst_device:
            dispatcher.utter_message(
                text=f"🎯 Both hosts are connected to the same device `{src_device}`.\n"
                     f"📍 {source_host} on {src_device}:{src_port}\n"
                     f"📍 {destination_host} on {dst_device}:{dst_port}\n"
                     f"🔄 Direct communication possible."
            )
            return []

        # Step 4: Find path
        path_result = send_to_healthy_controller(f"/onos/v1/paths/{src_device}/{dst_device}")
        if "error" in path_result or "paths" not in path_result or not path_result["paths"]:
            dispatcher.utter_message(text="⚠️ No path found between the hosts.")
            return []

        path = path_result["paths"][0]
        links = path.get("links", [])
        hops = []
        for link in links:
            src = link["src"]
            dst = link["dst"]
            hops.append(f"{src['device']}:{src['port']} ➡️ {dst['device']}:{dst['port']}")

        dispatcher.utter_message(
            text=f"🔍 **Path from {source_host} to {destination_host}:**\n"
                 f"📍 Start: {src_device}:{src_port}\n"
                 + "\n".join(hops) +
                 f"\n📍 End: {dst_device}:{dst_port}"
        )
        return []

# === Background task: Monitor controller health ===
#### Works ####
def push_alert_to_ui(text):
    try:
        requests.post(
            "http://localhost:5050/push_alert",  # This goes to your Flask mini server
            json={"alert": text}
        )
    except Exception as e:
        print(f"[Alert Push Error] {e}")

# Monitor Function
def monitor_controllers():
    down_set = set()

    while True:
        for ctrl in ONOS_CONTROLLERS:
            ip, port = ctrl["ip"], ctrl["port"]
            url = f"http://{ip}:{port}/onos/v1/cluster"

            try:
                res = requests.get(url, auth=AUTH, timeout=2)
                if res.status_code == 200:
                    if f"{ip}:{port}" in down_set:
                        print(f"✅ {ip}:{port} recovered")
                        down_set.remove(f"{ip}:{port}")
                else:
                    raise Exception()
            except:
                if f"{ip}:{port}" not in down_set:
                    down_set.add(f"{ip}:{port}")
                    alert = f"🔴 ALERT: Controller at {ip}:{port} is DOWN!"
                    print(f"[ALERT] {alert}")
                    try:
                        push_alert_to_ui(alert)
                    except Exception as e:
                        print(f"[UI Alert Error] {e}")

        time.sleep(10)

        # Only push alert if something went down in this cycle
        if down_set:
            for down in down_set:
                alert = f"🔴 ALERT: Controller at {down} is DOWN!"
                print(f"[ALERT] {alert}")
                push_alert_to_ui(alert)

def monitor_anomalies():
    print("[*] Starting anomaly monitor...")

    previous_stats = {}
    ANOMALY_THRESHOLD = 100  # packets
    POLL_INTERVAL = 5        # seconds

    while True:
        data = None

        # Try each controller until one responds
        for controller in ONOS_CONTROLLERS:
            try:
                url = f"http://{controller['ip']}:{controller['port']}/onos/v1/statistics/ports"
                response = requests.get(url, auth=AUTH, timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    break
            except Exception as e:
                print(f"[WARN] Failed to fetch from {controller['ip']}:{controller['port']} — {e}")

        if not data:
            print("[ERROR] All controllers unreachable.")
            time.sleep(POLL_INTERVAL)
            continue

        try:
            current_stats = {}
            anomalies = []

            for device in data.get("statistics", []):
                device_id = device.get("device")
                for port in device.get("ports", []):
                    port_number = str(port.get("port"))
                    packets_rx = port.get("packetsReceived", 0)
                    packets_tx = port.get("packetsSent", 0)

                    key = f"{device_id}:{port_number}"
                    current_stats[key] = (packets_rx, packets_tx)

                    if key in previous_stats:
                        prev_rx, prev_tx = previous_stats[key]
                        delta_rx = packets_rx - prev_rx
                        delta_tx = packets_tx - prev_tx

                        if delta_rx > ANOMALY_THRESHOLD or delta_tx > ANOMALY_THRESHOLD:
                            #msg = f"🚨 Anomaly on {key} → ΔRX: {delta_rx}, ΔTX: {delta_tx}"
                            msg = f"🚨 Anomaly Detected! \nDevice: {device_id} \nPort: {port_number} \nChange in Received Packets (ΔRX): {delta_rx} \nChange in Sent Packets (ΔTX): {delta_tx}\nPlease investigate."
                            print("[Anomaly]", msg)
                            push_alert_to_ui(msg)

            if not anomalies:
                print("[✓] No anomalies detected.")

            previous_stats = current_stats

        except Exception as e:
            print(f"[ERROR] in monitor_anomalies: {e}")

        time.sleep(POLL_INTERVAL)

# Start monitor thread on action server startup
threading.Thread(target=monitor_controllers, daemon=True).start()
threading.Thread(target=monitor_anomalies, daemon=True).start()
