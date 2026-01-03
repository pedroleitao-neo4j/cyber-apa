# Attack Path Analysis: Visualizing Lateral Movement and Exploitation Paths

This notebook demonstrates how to perform **Attack Path Analysis**, building and extending on the [Vulnerability Prioritization and Exposure Management (VPEM)](https://github.com/pedroleitao-neo4j/cyber-vpem) use case graph in Neo4j. By mapping the relationships between external endpoints, vulnerable compute instances, and sensitive internal resources, organizations can visualize and remediate the actual routes an attacker would take during a breach.

This is a critical extension of standard vulnerability management, shifting the focus from individual bugs to the **chained exploitation** that leads to data exfiltration.

## Use Case Overview

The Attack Path Analysis use case demonstrates how to:

* **Identify Footholds:** Locate internet-facing assets with critical, exploited vulnerabilities (Scenario A & C).
* **Visualize Lateral Movement:** Trace the internal network paths (`CAN_REACH`) that allow an attacker to move from a breached gateway to isolated internal workers (this is a new relationship added from the VPEM use case).
* **Map Impact to Crown Jewels:** Discover the final hop from a compromised internal host to a "P0" Tier application or sensitive cloud resource.

## Data Sources

To perform a full kill-chain analysis, we integrate the following data layers:

1. **Vulnerability & Threat Intel:** CVE data from **NVD** and exploitation status from **CISA KEV**.
2. **Network Topology:** Synthetic data representing internal network reachability (`CAN_REACH`) between compute instances.
3. **Identity & Cloud Access:** Relationships between applications, IAM identities, policies, and cloud services (e.g., S3 Buckets, PII Databases).

## The Graph Advantage

Traditional security tools often operate in silos—scanners see vulnerabilities, while firewalls see network rules. Neo4j unifies these views to perform **Multi-Hop Path Traversal**:

* **Beyond the Perimeter:** Visualizing how a vulnerability in a public-facing API acts as the "key" to an internal database.
* **Blast Radius Quantification:** Instantly calculating every resource an attacker can "touch" once they land on a specific node.
* **Chokepoint Identification:** Finding specific internal servers that act as gateways for multiple attack paths, making them high-value targets for hardening.

## Architecture

### Overview

The system utilizes a **Security Knowledge Graph** to map complex relationships in real-time. This architecture excels at identifying deep traversal paths that relational databases struggle to find, such as a 5-hop path from a CVE to a sensitive S3 bucket.

### Typical Data Flow

1. **Ingestion:** Loading CVE/KEV data and asset metadata into Neo4j.
2. **Path Simulation:** Injecting `CAN_REACH` relationships to simulate internal network accessibility.
3. **Exploration:** Running Cypher queries to find paths between `Endpoint` (Internet) and `Application {tier: 'P0'}` (Crown Jewels).
4. **Visualization:** Converting graph results into readable "Kill Chain" diagrams using `networkx`.

## Outward System Integration

The insights generated from Attack Path Analysis are pushed to:

* **Incident Response (SOAR):** To automatically contain breached nodes by revoking the specific IAM policies identified in the blast radius.
* **Security Architecture:** To prioritize **micro-segmentation** projects by identifying the most dangerous lateral movement routes.
* **Governance (GRC):** To provide "Reachability-to-Data" reports for compliance frameworks like SOC2 or PCI-DSS.# cyber-apa
