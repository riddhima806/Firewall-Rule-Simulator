from flask import Flask, render_template, request, redirect, Response
import random
import csv
import io

app = Flask(__name__)

# Global Firewall Rules & Logs
firewall_rules = [
    ("192.168.1.1", 80, "TCP", "block"),
    ("192.168.1.4", 53, "UDP", "block"),
    ("192.168.1.9", "*", "ICMP", "block"),
    ("192.168.1.13", 22, "TCP", "block"),
    ("*", 21, "TCP", "block"),
    ("192.168.1.16", "*", "*", "block")
]
logs = []  # 🔹 store logs here


def generate_random_ip():
    return f"192.168.1.{random.randint(0, 20)}"

def generate_random_port():
    return random.randint(1, 65535)

def generate_random_protocol():
    return random.choice(["TCP", "UDP", "ICMP"])

def check_firewall_rules(packet, rules):
    ip, port, protocol = packet
    ip = ip.strip()

    for rule_ip, rule_port, rule_protocol, action in rules:
        if (ip == rule_ip or rule_ip == "*") and \
           (port == rule_port or rule_port == "*") and \
           (protocol == rule_protocol or rule_protocol == "*"):
            return action
    return "allow"


@app.route("/", methods=["GET", "POST"])
def index():
    packets = []
    if request.method == "POST":
        for _ in range(10):  # simulate 10 packets
            ip_address = generate_random_ip()
            port = generate_random_port()
            protocol = generate_random_protocol()
            packet = (ip_address, port, protocol)
            action = check_firewall_rules(packet, firewall_rules)
            random_number = random.randint(0, 9999)
            result = (ip_address, port, protocol, action, random_number)

            packets.append(result)
            logs.append(result)   # 🔹 store in logs

    return render_template("index.html", rules=firewall_rules, packets=packets, logs=logs)


@app.route("/add_rule", methods=["POST"])
def add_rule():
    ip = request.form["ip"]
    port = request.form["port"]
    protocol = request.form["protocol"]
    action = request.form["action"]

    # keep port as int if not "*"
    if port != "*":
        port = int(port)

    firewall_rules.append((ip, port, protocol, action))
    return redirect("/")


@app.route("/clear_logs", methods=["POST"])
def clear_logs():
    logs.clear()
    return redirect("/")


@app.route("/download_logs")
def download_logs():
    # prepare CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP", "Port", "Protocol", "Action", "Random"])
    writer.writerows(logs)

    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=firewall_logs.csv"
    return response

if __name__ == "__main__":
    app.run(debug=True)
