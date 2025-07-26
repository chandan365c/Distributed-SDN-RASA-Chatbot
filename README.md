# Distributed-SDN-RASA-Chatbot

This project integrates a **5-node ONOS cluster**, **Mininet topology**, and a **RASA-powered chatbot UI** to monitor and manage an SDN network in real time. The setup is designed for **Ubuntu 24.04**.

---

## 📁 Directory Structure
```
.
├── actions/ # Custom RASA action code (Python)
├── data/ # Contains NLU, rules, and stories for RASA
├── models/, tests/ # RASA-related directories
├── rasa_chatbot_ui/ # Chatbot UI files including index.html
├── ui_alert_server.py # Custom alert server 
├── domain.yml, config.yml, etc. # RASA core config files
├── onos_cluster_setup.sh # Launches 5 ONOS controllers via Docker
├── karaf_ssh.sh # SSH into ONOS Karaf shells (8101–8105)
├── mininet_run.sh # Launches the SDN topology in Mininet

```
---
## 🧰 Prerequisites

Ensure the following are installed on **Ubuntu 24.04**:

- Docker & Docker Compose
- Mininet
- Python 3.8
- RASA (compatible with Python 3.8, preferably in a virtual environment)

---
## 🛠️ Project Setup and Execution

1. 🔃 Clone the Repository
Run ```git clone https://github.com/your-username/rasa-onos-monitoring.git``` and then ```cd rasa-onos-monitoring```

2. 🧠 Launch ONOS Cluster (5 controllers)
```./onos_cluster_setup.sh``` and wait for containers to fully start. Then verify ONOS UI using ```http://localhost:8181/onos/ui/#/topo2``` in the browser. You should see 5 controllers initialized.

3. 🔐 Access ONOS Karaf Shells
To access ONOS CLI on all 5 instances, run ```./karaf_ssh.sh```. This opens terminals for ports 8101–8105.

4. 🌐 Start Mininet Network
Execute the command ```sudo ./mininet_run.sh``` and then return to ONOS UI at ```http://localhost:8181/onos/ui/#/topo2``` and check the topology. You should now see the full network graph populated.

6. ⚙️ Start RASA Action Server
In the root directory with python3.8 virtual environment activated run ```rasa run actions```. This will run actions.py inside the actions/ folder.

7. 🧠 Start RASA Server
In a new terminal with the python3.8 virtual environment still activated, run ```rasa run --enable-api --cors "*" --debug```. This allows RASA to listen for chatbot queries via REST API.

8. 💬 Open the Chatbot UI
In another terminal, go to the UI directory and start a simple HTTP server by running ```python3 -m http.server 8000```. Then open the chatbot interface in your browser using the url ```🔗 http://localhost:8000```

---
## 🧪 Example Interactions

Try the following messages in the chatbot UI
```
"Show me the topology"

"List all devices"

"Get all flows on device of:0000000000000003"

"Add flow on device of:0000000000000003 with in port 1 and out port 2 and priority 55"

"Block host with IP 10.0.0.2"
```
These will trigger real-time API calls to your ONOS cluster and reflect changes in the topology.
