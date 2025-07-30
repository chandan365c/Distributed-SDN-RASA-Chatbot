import requests
from typing import Any, Text, Dict, List
from rasa_sdk import Action, Tracker
from rasa_sdk.executor import CollectingDispatcher
from rasa_sdk.events import SlotSet, EventType
import time
import json
import logging
import requests
import threading
from datetime import datetime
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

INFLUX_URL = "http://localhost:8086"
INFLUX_TOKEN = "lkyDDMbKr4XGNxD21XwJiTpiN--Wx4JUqhGEv6idbnC5Wn7N-nKRVoqQRYdm3zIM48JEy9LJDDhQFyDSQGRd8w=="
INFLUX_ORG = "sdn_org"
INFLUX_BUCKET = "sdn_metrics"

influx_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = influx_client.write_api(write_options=SYNCHRONOUS)


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configurable ONOS controllers (IPs and ports)
ONOS_CONTROLLERS = [
    {"ip": "localhost", "port": 8181},
    {"ip": "localhost", "port": 8182},
    {"ip": "localhost", "port": 8183},
    {"ip": "localhost", "port": 8184},
    {"ip": "localhost", "port": 8185},
]

AUTH = ("onos", "rocks")


# === Utility: Request with failover and mastership-aware ===
def send_to_healthy_controller(endpoint: str, method="get", data=None, json=None, device_id=None, require_mastership=False) -> Any:
    """
    Send request to a healthy ONOS controller with failover support.
    
    Args:
        endpoint: API endpoint to call
        method: HTTP method (get, post, put, delete)
        data: Request data for non-JSON payloads
        json: JSON payload for requests
        device_id: Device ID for mastership checks
        require_mastership: Whether to check mastership before sending request
    
    Returns:
        Response data or error dictionary
    """
    for ctrl in ONOS_CONTROLLERS:
        try:
            # If checking mastership is required
            if require_mastership and device_id:
                master_url = f"http://{ctrl['ip']}:{ctrl['port']}/onos/v1/mastership/{device_id}"
                try:
                    master_resp = requests.get(master_url, auth=AUTH, timeout=2)
                    if master_resp.ok:
                        master_data = master_resp.json()
                        master_id = master_data.get("master", {}).get("id", "")
                        # Check if this controller is the master
                        if master_id and f"{ctrl['ip']}:{ctrl['port']}" not in master_id:
                            logger.info(f"Controller {ctrl['ip']}:{ctrl['port']} is not master for device {device_id}")
                            continue
                    else:
                        logger.warning(f"Failed to check mastership on {ctrl['ip']}:{ctrl['port']}")
                        continue
                except requests.RequestException as e:
                    logger.warning(f"Mastership check failed for {ctrl['ip']}:{ctrl['port']}: {e}")
                    continue

            # Send the actual request
            url = f"http://{ctrl['ip']}:{ctrl['port']}{endpoint}"
            logger.info(f"Sending {method.upper()} request to {url}")
            
            resp = requests.request(method, url, auth=AUTH, timeout=5, data=data, json=json)
            
            if resp.ok:
                # Return JSON if content type is JSON, otherwise return text
                if resp.headers.get("Content-Type", "").startswith("application/json"):
                    return resp.json()
                else:
                    return {"status": "success", "message": resp.text}
            else:
                logger.warning(f"Request failed with status {resp.status_code}: {resp.text}")
                
        except requests.RequestException as e:
            logger.warning(f"Request to {ctrl['ip']}:{ctrl['port']} failed: {e}")
            time.sleep(0.1)  # Small delay before trying next controller
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
        for ctrl in ONOS_CONTROLLERS:
            url = f"http://{ctrl['ip']}:{ctrl['port']}/onos/v1/devices/{device_id}"
            try:
                response = requests.get(url, auth=('onos', 'rocks'), timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("role") == "MASTER":
                        return ctrl['ip'], ctrl['port']
            except Exception:
                continue
        return None, None

    async def run(self, dispatcher, tracker, domain):
        device_id = self.extract_slot("device_id", tracker)
        in_port = self.extract_slot("in_port", tracker)
        out_port = self.extract_slot("out_port", tracker)
        priority = self.extract_slot("priority", tracker)

        if not all([device_id, in_port, out_port, priority]):
            dispatcher.utter_message(text="⚠️ Missing values: device ID, input/output ports, or priority. Please provide all required details.")
            return []

        master_ip, master_port = self.find_master_controller(device_id)
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

        url = f"http://{master_ip}:{master_port}/onos/v1/flows/{device_id}"
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

                    host_list.append(f"🏠 {host_id} (MAC: {mac}, IP: {ip})")

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
            dispatcher.utter_message(text="⚠️ Please provide a valid host IP address.")
            return []

        for controller in ONOS_CONTROLLERS:
            ip = controller["ip"]
            port = controller["port"]
            base_url = f"http://{ip}:{port}/onos/v1"
            auth = ("onos", "rocks")

            try:
                # 1. Get list of hosts
                host_response = requests.get(f"{base_url}/hosts", auth=auth, timeout=2)
                if host_response.status_code != 200:
                    continue

                hosts = host_response.json().get("hosts", [])
                matched_host = next((h for h in hosts if host_id in h.get("ipAddresses", [])), None)

                if not matched_host:
                    continue

                location = matched_host["locations"][0]
                device_id = location["elementId"]

                # 2. Build the drop flow using IPV4_SRC match and no treatment
                flow_rule = {
                    "priority": 45000,
                    "timeout": 0,
                    "isPermanent": True,
                    "deviceId": device_id,
                    "treatment": {
                        "instructions": []  # No instructions => drop
                    },
                    "selector": {
                        "criteria": [
                            {
                                "type": "ETH_TYPE",
                                "ethType": "0x0800"
                            },
                            {
                                "type": "IPV4_SRC",
                                "ip": f"{host_id}/32"
                            }
                        ]
                    }
                }

                # 3. Push the flow
                flow_url = f"{base_url}/flows/{device_id}"
                response = requests.post(flow_url, json=flow_rule, auth=auth, timeout=3)

                if response.status_code in [200, 201, 204]:
                    dispatcher.utter_message(text=f"🚫 Traffic from host {host_id} has been blocked on {device_id}.")
                    return []
                else:
                    print(f"[WARN] Flow install failed on {ip}:{port} — status {response.status_code}")

            except Exception as e:
                print(f"[ERROR] Controller {ip}:{port} failed: {e}")
                continue

        dispatcher.utter_message(text=f"❌ Failed to block host {host_id}. Could not reach any controller.")
        return []


# === Action: Unblock Host ===
class ActionUnblockHost(Action):
    def name(self) -> str:
        return "action_unblock_host"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        raw_host = tracker.get_slot("host_id")
        if not raw_host:
            dispatcher.utter_message(text="⚠️ Please specify a host IP or MAC to unblock.")
            return []

        # Normalize IP or MAC
        if ":" in raw_host:  # assume MAC
            normalized = raw_host.lower()
            match_field = "mac"
            match_type = "ETH_DST"
        else:  # assume IP
            normalized = raw_host if "/" in raw_host else raw_host + "/32"
            match_field = "ip"
            match_type = "IPV4_SRC"

        logger.info(f"[Unblock] Looking for {match_type} = {normalized}")

        found = False

        for ctrl in ONOS_CONTROLLERS:
            try:
                url = f"http://{ctrl['ip']}:{ctrl['port']}/onos/v1/flows"
                resp = requests.get(url, auth=AUTH, timeout=3)
                if resp.status_code != 200:
                    continue

                flows = resp.json().get("flows", [])
                for flow in flows:
                    device_id = flow["deviceId"]
                    flow_id = flow["id"]
                    criteria = flow.get("selector", {}).get("criteria", [])

                    for criterion in criteria:
                        if criterion.get("type") == match_type and normalized in criterion.get(match_field, ""):
                            # Match found — delete it
                            del_url = f"http://{ctrl['ip']}:{ctrl['port']}/onos/v1/flows/{device_id}/{flow_id}"
                            del_resp = requests.delete(del_url, auth=AUTH, timeout=3)
                            if del_resp.status_code in [200, 204]:
                                dispatcher.utter_message(text=f"✅ Unblocked host `{raw_host}` by deleting flow `{flow_id}` on {device_id}.")
                                logger.info(f"[Unblock] Deleted flow {flow_id} from {device_id}")
                                return []
                            else:
                                logger.warning(f"[Unblock] Failed to delete flow {flow_id} from {device_id}")
            except Exception as e:
                logger.error(f"[ERROR] Could not contact controller {ctrl['ip']}:{ctrl['port']} - {e}")
                continue

        dispatcher.utter_message(text=f"❌ No matching flow found to unblock host `{raw_host}`.")
        return []


# === Action: Get Ports ===
class ActionGetPorts(Action):
    def name(self) -> str:
        return "action_get_ports"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[str, Any]) -> List[EventType]:
        device_id = tracker.get_slot("device_id")
        if not device_id:
            dispatcher.utter_message(text="⚠️ Please specify a device ID (e.g., 'show ports on device of:0000000000000001')")
            return []
        
        logger.info(f"Getting ports for device: {device_id}")
        result = send_to_healthy_controller(f"/onos/v1/devices/{device_id}/ports")
        
        if "error" in result:
            dispatcher.utter_message(text=f"❌ Failed to fetch ports for device {device_id}.")
        else:
            ports = result.get("ports", [])
            if ports:
                port_list = []
                for port in ports:
                    port_num = port.get("port", "Unknown")
                    enabled = "✅" if port.get("isEnabled", False) else "❌"
                    speed = port.get("portSpeed", "Unknown")
                    port_list.append(f"{enabled} Port {port_num} (Speed: {speed})")
                
                message = f"🔌 **Ports on {device_id} ({len(ports)}):**\n" + "\n".join(port_list)
                dispatcher.utter_message(text=message)
            else:
                dispatcher.utter_message(text=f"📭 No ports found on device {device_id}.")
        
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
            dispatcher.utter_message(text="⚠️ Please specify a device ID (e.g., 'show flows on device of:0000000000000001')")
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

# Show port statistics
class ActionShowPortStats(Action):
    def name(self) -> Text:
        return "action_show_port_stats"

    def run(self, dispatcher, tracker, domain):
        result = send_to_healthy_controller("/onos/v1/statistics/ports")

        if "error" in result:
            dispatcher.utter_message(text="❌ Failed to fetch port statistics from any controller.")
            return []

        messages = ["📊 **Port Statistics Summary:**"]
        for device in result.get("statistics", []):
            device_id = device.get("device", "Unknown")
            for port in device.get("ports", []):
                port_no = port.get("port", "N/A")
                rx = port.get("packetsReceived", 0)
                tx = port.get("packetsSent", 0)
                messages.append(f"🔌 {device_id}:{port_no} → RX: {rx}, TX: {tx}")

        dispatcher.utter_message(text="\n".join(messages))
        return []

def monitor_topology_health():
    print("[*] Monitoring switches and links...")

    known_devices = set()
    known_links = set()

    while True:
        try:
            for ctrl in ONOS_CONTROLLERS:
                url_devices = f"http://{ctrl['ip']}:{ctrl['port']}/onos/v1/devices"
                url_links = f"http://{ctrl['ip']}:{ctrl['port']}/onos/v1/links"
                resp_d = requests.get(url_devices, auth=AUTH, timeout=2)
                resp_l = requests.get(url_links, auth=AUTH, timeout=2)

                if resp_d.status_code == 200 and resp_l.status_code == 200:
                    devices_json = resp_d.json()
                    links_json = resp_l.json()

                    current_devices = set(
                        d["id"] for d in devices_json.get("devices", []) if d.get("available", False)
                    )

                    current_links = set(
                        f"{l['src']['device']}->{l['dst']['device']}"
                        for l in links_json.get("links", [])
                    )

                    # Detect down devices or links
                    missing_devices = known_devices - current_devices
                    missing_links = known_links - current_links

                    for d in missing_devices:
                        print(f"🚨 Switch offline: {d}")
                        push_alert_to_ui(f"🚨 Switch offline: {d}")
                    for l in missing_links:
                        print(f"🚨 Link down: {l}")
                        push_alert_to_ui(f"🚨 Link down: {l}")

                    known_devices = current_devices
                    known_links = current_links
                    break

        except Exception as e:
            print(f"[ERROR] in topology monitor: {e}")

        time.sleep(5)
        

#Show flow statistics
class ActionShowFlowStats(Action):
    def name(self) -> Text:
        return "action_show_flow_stats"

    def run(self, dispatcher, tracker, domain):
        result = send_to_healthy_controller("/onos/v1/devices")

        if "error" in result:
            dispatcher.utter_message(text="❌ Could not fetch device list.")
            return []

        devices = result.get("devices", [])
        if not devices:
            dispatcher.utter_message(text="📭 No devices found.")
            return []

        messages = ["📈 Flow Stats by Device:"]
        for device in devices:
            device_id = device.get("id")
            flow_result = send_to_healthy_controller(f"/onos/v1/flows/{device_id}")
            if "error" in flow_result:
                messages.append(f"❌ {device_id}: Failed to fetch flow info")
                continue

            flow_count = len(flow_result.get("flows", []))
            messages.append(f"🔁 {device_id}: {flow_count} flows")

        dispatcher.utter_message(text="\n".join(messages))
        return []

# Export flow metrics
class ActionExportFlowMetrics(Action):
    def name(self) -> Text:
        return "action_export_flow_metrics"

    def run(self, dispatcher, tracker, domain):
        try:
            devices_resp = send_to_healthy_controller("/onos/v1/devices")
            if "error" in devices_resp:
                dispatcher.utter_message(text="❌ Could not fetch device list for flow stats export.")
                return []

            devices = devices_resp.get("devices", [])
            now = datetime.utcnow()

            for device in devices:
                device_id = device.get("id")
                flow_resp = send_to_healthy_controller(f"/onos/v1/flows/{device_id}")
                if "error" in flow_resp:
                    continue

                flow_count = len(flow_resp.get("flows", []))

                point = Point("flow_stats") \
                    .tag("device", device_id) \
                    .field("flow_count", flow_count) \
                    .time(now, WritePrecision.NS)

                write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)

            dispatcher.utter_message(text="✅ Flow stats exported to InfluxDB for Grafana.")
        except Exception as e:
            dispatcher.utter_message(text=f"❌ Error exporting flow metrics: {e}")
        return []

#Export metrics
class ActionExportMetrics(Action):
    def name(self) -> Text:
        return "action_export_metrics"

    def run(self, dispatcher, tracker, domain):
        try:
            result = send_to_healthy_controller("/onos/v1/statistics/ports")
            now = datetime.utcnow()

            for device in result.get("statistics", []):
                device_id = device.get("device")
                for port in device.get("ports", []):
                    port_no = str(port.get("port"))
                    rx = port.get("packetsReceived", 0)
                    tx = port.get("packetsSent", 0)

                    point = Point("port_traffic") \
                        .tag("device", device_id) \
                        .tag("port", port_no) \
                        .field("rx", rx) \
                        .field("tx", tx) \
                        .time(now, WritePrecision.NS)

                    write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)

            dispatcher.utter_message(text="✅ Port stats exported to InfluxDB for Grafana.")
        except Exception as e:
            dispatcher.utter_message(text=f"❌ Error exporting metrics: {e}")
        return []

#Push stats periodically
def push_port_stats_periodically():
    while True:
        try:
            result = send_to_healthy_controller("/onos/v1/statistics/ports")
            now = datetime.utcnow()

            for device in result.get("statistics", []):
                device_id = device.get("device")
                for port in device.get("ports", []):
                    port_no = str(port.get("port"))
                    rx = port.get("packetsReceived", 0)
                    tx = port.get("packetsSent", 0)

                    point = Point("port_traffic") \
                        .tag("device", device_id) \
                        .tag("port", port_no) \
                        .field("rx", rx) \
                        .field("tx", tx) \
                        .time(now, WritePrecision.NS)

                    write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)

            print("[✓] Port stats pushed to InfluxDB.")
        except Exception as e:
            print(f"[ERROR] Periodic export failed: {e}")

        time.sleep(5)

# Monitor Function
def monitor_controllers():
    down_set = set()

    while True:
        alert = None
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

def classify_anomaly(delta_rx, delta_tx):
    total = delta_rx + delta_tx
    if total > 5000:
        return "🔥 Possible DoS or heavy traffic spike"
    elif delta_rx > 3000 and delta_tx < 100:
        return "🕵️ Suspicious inbound spike (port scan or flood)"
    elif delta_tx > 3000 and delta_rx < 100:
        return "⚠️ Suspicious outbound spike (data exfiltration?)"
    elif 1000 < total <= 5000:
        return "📶 Moderate traffic spike"
    else:
        return "❓ Unknown anomaly pattern"


ANOMALY_LOG_FILE = "anomalies.log"

def monitor_anomalies():
    print("[*] Starting anomaly monitor...")

    previous_stats = {}
    ANOMALY_THRESHOLD = 100  # packets
    POLL_INTERVAL = 5        # seconds

    while True:
        data = None
        hosts_data = None

        # Try each controller until one responds
        for controller in ONOS_CONTROLLERS:
            try:
                stats_url = f"http://{controller['ip']}:{controller['port']}/onos/v1/statistics/ports"
                hosts_url = f"http://{controller['ip']}:{controller['port']}/onos/v1/hosts"

                stats_response = requests.get(stats_url, auth=AUTH, timeout=3)
                hosts_response = requests.get(hosts_url, auth=AUTH, timeout=3)

                if stats_response.status_code == 200 and hosts_response.status_code == 200:
                    data = stats_response.json()
                    hosts_data = hosts_response.json()
                    break
            except Exception as e:
                print(f"[WARN] Failed to fetch from {controller['ip']}:{controller['port']} — {e}")

        if not data or not hosts_data:
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
                            anomalies.append((device_id, port_number, delta_rx, delta_tx))

            if anomalies:
                hosts = hosts_data.get("hosts", [])
                for device_id, port_number, delta_rx, delta_tx in anomalies:

                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    # Try to match host to this port
                    suspect_host = None
                    for host in hosts:
                        for loc in host.get("locations", []):
                            if loc.get("elementId") == device_id and str(loc.get("port")) == port_number:
                                ip = host.get("ipAddresses", ["?"])[0]
                                mac = host.get("mac", "?")
                                suspect_host = f"{ip} ({mac})"
                                break

                    classification = classify_anomaly(delta_rx, delta_tx)
                    msg = (
                        f"[{timestamp}] 🚨 Anomaly Detected on {device_id}:{port_number} → ΔRX: {delta_rx}, ΔTX: {delta_tx}\n"
                        f"🔎 Type: {classification}"
                    )
                    if suspect_host:
                        msg += f"\n❓ Suspected Host: {suspect_host}\n🛡️ Suggestion: Block host {suspect_host}"

                    print("[Anomaly]", msg)
                    push_alert_to_ui(msg)

                    # Log to file
                    with open(ANOMALY_LOG_FILE, "a") as f:
                        f.write(msg + "\n")

            else:
                print("[✓] No anomalies detected.")

            previous_stats = current_stats

        except Exception as e:
            print(f"[ERROR] in monitor_anomalies: {e}")

        time.sleep(POLL_INTERVAL)

# Start monitor thread on action server startup
threading.Thread(target=monitor_controllers, daemon=True).start()
threading.Thread(target=monitor_anomalies, daemon=True).start()
threading.Thread(target=push_port_stats_periodically, daemon=True).start()
threading.Thread(target=monitor_topology_health, daemon=True).start()
