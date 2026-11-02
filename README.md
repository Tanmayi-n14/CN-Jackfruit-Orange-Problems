
# Remote Device Control & Monitoring System
### Project #24 — TCP/IP Socket-Based IoT Infrastructure

---

## 1. Contributors
* **Tanmayi** — PES1UG24CS493
* **Tanisha** — PES1UG24CS491
* **Pavithra** — PES1UG24CS489

---

## 2. Project Objectives
The objective of this system is to establish a high-reliability, full-duplex communication bridge between an Edge IoT Device and a Central Controller.

By utilizing raw TCP/IP sockets, the project demonstrates a "zero-middleware" approach to industrial monitoring, specifically focusing on Fault Tolerance, Hardware Longevity, and Resilient Design.

---


## 3. Interactive Dashboard (index.html)
The core of this submission is the web-based monitoring interface. It provides a real-time visualization of the 6 engineering challenges and the active socket state.

Full System Demo: An integrated script allows for a "One-Click" simulation of all failure and recovery scenarios.

Real-time Diagnostics: Visualizes the Moving-Average filter absorbing EMI spikes and the Watchdog timer tracking cooling efficiency.

Hardware Simulation: Models the relay isolation barrier between low-voltage logic and 230V AC loads.


---

## 4. Environment & Topology
The project architecture emulates a real-world industrial monitoring environment:

* **Controller Node:** A Python-based Server running on `127.0.0.1:65432`.
* **Edge Device Node:** A simulated IoT client that injects EMI-style sensor noise for testing.
* **Data Plane:** Raw TCP Sockets providing guaranteed, ordered delivery of JSON-formatted telemetry.

**Execution Commands:**

```bash
# Terminal 1: Initialize the Controller (Server)
python controller.py

# Terminal 2: Initialize the IoT Device (Client)
python device_mock.py
```

---

## 5. Implementation Logic (controller.py)
The controller is built using reactive logic in Python. It parses incoming packets and maintains safety state variables (lockouts, averages, and timestamps) to protect the physical hardware.

```python
def start_smart_controller():
    # --- LOGGING BY TANMAYI (493), TANISHA (491), PAVITHRA (489) ---
    print("\n" + "="*30)
    print(" [TELEMETRY LOGGED] ")
    
    # --- PHASE 1: SENSOR FILTERING ---
    raw_temp = json.loads(data.decode())["temp"]
    readings.append(raw_temp)
    avg = sum(readings) / len(readings)
    
    # --- PHASE 2: SAFETY DISPATCH ---
    if avg >= THRESH_HIGH:
        if now - last_off_ts >= SC_LOCKOUT:
            command = "LED_ON"
    elif avg <= THRESH_LOW:
        command = "LED_OFF"
    
    print(f" RAW: {raw_temp} | AVG: {avg:.1f} | CMD: {command}")
    print("="*30)
```

---

## 6. Detailed Engineering Challenges

### I. Short-Cycle Protection (Compressor Safety)
* **The Logic**: We implemented a `SC_LOCKOUT` constant to simulate industrial compressor delay.
* **Mechanism**: Once the AC enters an `OFF` state, a timestamp is recorded. The controller blocks any `LED_ON` commands for a 15-second window, regardless of temperature readings.
* **Benefit**: This mimics the "Minimum Off Time" used in professional HVAC systems to prevent motor burnout.

### II. Moving-Average Filter (Signal De-noising)
* **The Logic**: A `collections.deque` with a `maxlen=10` is used to maintain a rolling window of telemetry.
* **Mechanism**: The controller calculates the arithmetic mean of the window before making a threshold decision.
* **Benefit**: Successfully ignores EMI-induced glitch spikes that would otherwise trigger false emergency cooling.

### III. Watchdog Timer (Hardware Feedback Loop)
* **The Logic**: A software watchdog monitors the "Cooling Efficiency" of the system.
* **Mechanism**: When the AC is toggled `ON`, the system benchmarks the current temperature. If a temperature drop of $\ge 1.5^{\circ}C$ is not detected within 15 seconds, a `MAINTENANCE` alarm is fired.
* **Benefit**: Identifies physical failures like refrigerant leaks or open doors by observing the feedback loop.

### IV. Relay Interfacing & Electrical Isolation
* **The Logic**: The project simulates the **Galvanic Isolation** layer necessary for industrial control.
* **Mechanism**: The code models the interaction where 3.3V logic (GPIO) energizes an electromagnetic coil to switch a 230V AC load.
* **Benefit**: Protects sensitive microcontroller circuitry from high-voltage back-EMF and inductive surges.

### V. Multi-Stage PWM Fan Control
* **The Logic**: Implements a 4-stage Pulse Width Modulation (PWM) simulation for energy efficiency.
* **Mechanism**: Fan speed is dynamically adjusted (Low, Medium, High, Max) based on the deviation from the target threshold.
* **Benefit**: Mimics modern Inverter-class appliances to reduce acoustic noise and optimize power consumption.

### VI. Non-Volatile State Recovery (NVRAM)
* **The Logic**: Thresholds and operating modes are committed to a persistent storage layer.
* **Mechanism**: Upon initialization, the script checks for a saved state to resume operations without manual reconfiguration.
* **Benefit**: Ensures 24/7 autonomous reliability even in industrial environments prone to power instability.

---

## 7. Performance Observation & Analysis

| Feature | Implementation | Result |
| :--- | :--- | :--- |
| **Data Protocol** | TCP Socket | 100% Reliable, Ordered Delivery |
| **Noise Filtering** | MA Window (10) | EMI Spikes Absorbed; System Stable |
| **Fault Detection** | Watchdog Timer | 100% Identification of Cooling Failure |
| **State Persistence** | NVRAM Simulation | Resumes Mode/Threshold after Power Cut |

**Observation**: The system successfully demonstrated the ability to prioritize hardware safety over immediate responsiveness. During testing, the **Short-Cycle Lockout** effectively blocked multiple "Turn ON" requests during the cooldown phase, ensuring the simulated hardware was never subjected to unsafe pressure levels.

---

## 8. ICMP-Based Network Diagnostic Suite (Ping & Traceroute)

Located in [`icmp_network_diagnostic_suite/`](./icmp_network_diagnostic_suite).

### Architecture & Capabilities:
* **Raw Sockets**: Uses raw `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` for low-level network packet crafting.
* **Internet Checksum**: RFC 1071 one's complement 16-bit checksum computation in `checksum.py` and `icmp_core.c`.
* **Ping Engine (`ping_engine.py` — Tanmayi)**:
  * Manages iterative ICMP Echo Requests with strict sequence numbering.
  * Calculates real-time Round Trip Time (RTT): min, avg, max, and packet loss percentage.
  * Robust error handling for request timeouts and network unreachable signals.
* **Core Packet Engine (`icmp_core.py` — Tanisha)**:
  * Packet serialization, TTL manipulation for Traceroute hop discovery, and response parsing.
* **Frontend Dashboard**:
  * `dashboard.html` visualizing live probe statistics and network health.

### Execution:
```bash
cd icmp_network_diagnostic_suite
# Run Ping Engine (requires sudo/administrator privileges for raw ICMP sockets)
python -m core.ping_engine
```

---

## 9. Level 2 Orange Project: SDN Packet Logger
The SDN OpenFlow controller and Mininet experiment are archived on the dedicated branch:
👉 [**Branch: `SDN-orange-problem-Tanmayi-CS493`**](../../tree/SDN-orange-problem-Tanmayi-CS493)
* Custom POX controller application (`logger.py`) logging MAC/IP headers at switch `s1`.
* Complete Mininet 3-host reactive flow management proof with Ubuntu VirtualBox screenshots.

