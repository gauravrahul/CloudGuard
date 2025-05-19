# CloudGuard

**CloudGuard** is a cloud-integrated, real-time DDoS detection and mitigation system built with Go, AWS, and WebSockets. It monitors live network traffic, detects intrusion patterns, and provides actionable controls via an interactive web dashboard.

---

## 🚀 Features

* **Real-Time Network Traffic Monitoring**
  Captures and analyzes live packets using `gopacket` and Go routines.

* **DDoS Detection and Signature-Based Threat Identification**
  Detects threats like SYN Floods, SQL Injection, HTTP floods, and suspicious browser behavior.

* **WebSocket-Powered Live Dashboard**
  Instant updates of attack stats, logs, and metrics via WebSockets.

* **AWS Integration**
  Automatically blocks malicious IPs using AWS WAF. Uses DynamoDB for attack log persistence.

* **Visual Analytics and Charts**

  * Attack Type Distribution (Pie Chart)
  * Traffic Trends (Line Chart)
  * Threat Summary (Tabular View)

* **User Authentication and Session Management**
  Secure login, signup, and session control.

* **Exportable Reports**
  Generate and export attack summaries by date.

---

## 🧰 Tech Stack

* **Backend**: Go (Golang)

  * gopacket (packet capture)
  * AWS SDK v2
  * gorilla/websocket

* **Frontend**: HTML, JavaScript, CSS

  * Chart.js
  * REST + WebSocket APIs

* **Cloud Services**: AWS

  * WAF
  * DynamoDB

---

## 📁 Directory Structure

```
├── cmd/                 # main.go entry point
├── config/              # config.json and loader
├── detection/           # Analyzer, Packet Capture, Signature Matching
├── storage/             # DynamoDB integration and handlers
├── web/                 # HTML, JS, CSS files (Dashboard, Logs, Reports)
├── api.go               # REST API handlers
├── websocket.go         # WebSocket server logic
├── types.go             # Data models
├── signatures.json      # Attack signature definitions
```

---

## ⚙️ Setup Instructions

1. **Install Go** (v1.19 or later recommended)

2. **Clone the Repository**

```bash
git clone https://github.com/gauravrahul/CloudGuard.git
cd CloudGuard
```

3. **Configure AWS Credentials**

* IAM user with access to DynamoDB and WAF
* Configure credentials using AWS CLI or environment variables

4. **Edit `config.json`**

* Set interface name, AWS region, table names, WAF IP set ID, etc.

5. **Run the Backend**

```bash
go run cmd/main.go
```

6. **Open the Dashboard**
   Visit: [http://localhost:8080/login.html](http://localhost:8080/login.html)

---

## 📊 Screenshots

* 📈 Live Traffic Charts
* 🧠 Real-Time Threat Summary
* 📋 Real-Time Attack Logs

(*Screenshots available in `/screenshots` folder or GitHub issue attachments*)

---

## 🧪 In Progress

* Docker containerization
* System validation scripts
* Advanced threat correlation engine

---

## 👨‍💻 Contributors

* [KushaalGP](mailto:kushaalgp@gmail.com)
* [LikithG1](mailto:likithg0111@gmail.com)

---

## 📜 License

MIT License. See `LICENSE` file for details.

---

## 📞 Contact

If you have questions, open an [Issue](https://github.com/gauravrahul/CloudGuard/issues) or reach out via email.

---

**CloudGuard**: Real-time threat detection meets cloud-scale mitigation.
