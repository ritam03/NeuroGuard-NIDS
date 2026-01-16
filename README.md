# 🛡️ NeuroGuard: AI-Powered Network Intrusion Detection System (NIDS)

**NeuroGuard** is a robust, real-time Network Intrusion Detection System designed to secure local networks against cyber threats. By combining **Machine Learning (XGBoost)** with **Heuristic Traffic Analysis**, it detects both known attack patterns and high-velocity Denial of Service (DoS) floods with professional-grade precision.

---

## 🚀 Key Features

* **Real-Time Packet Sniffing:** Captures live network traffic (TCP, UDP, ICMP) using raw sockets for immediate analysis.
* **Hybrid Detection Engine:**
    * **AI Layer:** Uses a pre-trained XGBoost classifier to analyze packet signatures against 41 specific network features.
    * **Heuristic Layer:** Implements a "Sliding Time Window" mechanism to detect Volumetric Attacks (DoS/DDoS) based on traffic rate.
* **High Accuracy:** Achieving **99.65% Accuracy** and **99.51% Recall** using a Unified Learning Strategy on the NSL-KDD dataset.
* **Live Traffic Classification:** Instantly classifies packets as "Normal" or "Malicious" and provides detailed logs including Source IP, Destination IP, Protocol, and Threat Confidence.
* **Dynamic Feature Extraction:** Converts raw binary packets into statistical features (Duration, Service, Flag, Source Bytes, etc.) on the fly, bridging the gap between raw network data and AI inputs.

---

## 🧠 System Architecture & Algorithms

### 1. The Dataset Strategy (Unified Learning)
The system is trained on the **NSL-KDD** dataset, the industry standard for intrusion detection benchmarking. Unlike traditional approaches that struggle with unknown attacks, NeuroGuard employs a **Unified Learning Strategy**:
* **Data Fusion:** Combines Training and Testing sets (`KDDTrain+`, `KDDTest+`) into a comprehensive knowledge base.
* **Stratified Split:** Re-splits data (80/20) to ensure the model learns diverse attack signatures (DoS, Probe, U2R, R2L) rather than overfitting to specific file structures.

### 2. The Core Algorithm: XGBoost Classifier
We utilize **eXtreme Gradient Boosting (XGBoost)**, a highly efficient implementation of gradient boosted decision trees, chosen for its superiority in cybersecurity tasks.
* **Why XGBoost?** It consistently outperforms Random Forest and SVM in tabular data classification, offering faster execution speeds for real-time inference and superior handling of imbalanced datasets.
* **Optimization:** The model is optimized for log-loss reduction with specific hyperparameters (`max_depth=6`, `learning_rate=0.1`) to balance sensitivity and specificity.

### 3. Traffic Rate Tracking (Heuristics)
To prevent model evasion via high-speed flooding, the system tracks the packet velocity of every connected IP:
* **Sliding Window:** Resets traffic counters every 2 seconds.
* **Thresholding:** If an IP exceeds the request limit (e.g., >50 packets/sec) within the window, it is flagged immediately as a Denial of Service (DoS) attempt, providing a failsafe against attacks that might mimic normal traffic signatures.

---

## 📊 Performance Metrics

The system was evaluated against multiple algorithms to ensure optimal performance. **XGBoost** was selected as the final engine due to its superior Attack Recall.

| Algorithm | Accuracy | Attack Recall | F1 Score |
| :--- | :--- | :--- | :--- |
| **XGBoost (Selected)** | **99.65%** | **99.51%** | **0.9964** |
| Random Forest | 99.61% | 99.46% | 0.9959 |
| Decision Tree | 99.19% | 98.94% | 0.9915 |

* **Accuracy:** The overall correctness of the system (Normal vs. Attack).
* **Attack Recall:** The most critical metric for security—it measures the percentage of actual attacks the system successfully detected (avoiding False Negatives).
