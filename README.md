
# ASTRID
### Real-time Signals for Open Source AI Momentum

**Astrid is a distributed backend system designed to provide a third, predictive pillar of AI adoption analysis by tracking the real-time momentum of open-source, developer-first AI tools.**

---

### A Leading Indicator for the AI Economy

The modern AI landscape is measured in two primary ways:
1.  **The Survey View:** What firms *say* they do, captured by crucial research like the U.S. Census Bureau's "[Tracking Firm Use of AI in Real Time](https://www2.census.gov/ces/wp/2024/CES-WP-24-16.pdf)" (Bonney et al., 2024).
2.  **The Transactional View:** What firms *pay* for, measured authoritatively by the [Ramp AI Index](https://ramp.com/economics/ai-index).

Both methodologies are essential, yet both acknowledge a critical blind spot: the vast, dynamic ecosystem of **free and open-source software (FOSS)**. This is where developer attention—the most valuable leading indicator in the tech economy—congregates first.

**Astrid is an open-source data engine built to fill this exact gap.**

By aggregating and analyzing high-signal public data from developer-native platforms like GitHub, Hacker News, and PyPI, Astrid functions as a **leading indicator engine**. It aims to quantify the ground-truth developer activity that precedes formal corporate adoption and commercial spending, providing a complementary dataset to the foundational work done by the Census Bureau and Ramp.

### System Architecture

Astrid is architected as a resilient, observable, and scalable data pipeline deployed on Kubernetes. The system is designed with a clear separation of concerns, using a message queue to decouple asynchronous data ingestion from processing and storage.

```plaintext
                                    ┌────────────────────────────────┐
                                    │         Cloud Environment      │
                                    │                                │
┌────────────┐                      │  ┌──────────────────────────┐  │
│ GitHub     ├─(Cron Trigger)───────┼─▶│ Kubernetes Cluster       │  │
│ Actions    │                      │  │                          │  │
└────────────┘                      │  │  ┌──────────┐            │  │
                                    │  │  │  Astrid  │ (Nightly)  │  │
                                    │  │  │ Producer │ (K8s Job)  │  │
                                    │  │  └────┬─────┘            │  │
                                    │  └───────│──────────────────┘  │
                                    │          │ (Jobs pushed)       │
                                    │          ▼                     │
┌─────────────────────────┐         │  ┌──────────────────────────┐  │
│ Managed RabbitMQ        │◀─ ─ ─ ──┼─▶│ Kubernetes Cluster       │  │
│ (e.g., CloudAMQP)       │         │  │                          │  │
└─────────────────────────┘         │  │  ┌──────────┐            │  │
            ▲                       │  │  │  Astrid  │ (AsyncIO)  │  │
            │ (Data ingested)       │  │  │  Workers │(Deployment)│  │
            │                       │  │  └────┬─────┘            │  │
┌─────────────────────────┐         │  └───────│──────────────────┘  │
│ Managed PostgreSQL      │◀─ ─ ─ ──┼ ─ ─ ─ ─ ─│──────────────────┘  │
│ /w TimescaleDB (Neon)   |         │  └───────│──────────────────┘  │
└─────────────────────────┘         │          │                     │
                                    │          ▼                     │
                                    │  ┌──────────────────────────┐  │
                                    │  │ Kubernetes Cluster       │  │
                                    │  │                          │  │
                                    │  │  ┌──────────┐            │  │
                                    │  │  │ FastAPI  │◀──(Public) │  │
                                    │  │  │   API    │(Deployment)│  │
                                    │  │  │ (& /metrics)          │  │
                                    │  │  └──────────┘            │  │
                                    │  └──────────────────────────┘  │
                                    └────────────────────────────────┘
```
The system's metrics are scraped by a Prometheus instance and visualized in Grafana Cloud.

### Stack & Rationale

| Category      | Technology                        | Rationale                                                                                                       |
| :------------ | :-------------------------------- | :-------------------------------------------------------------------------------------------------------------- |
| **Orchestration** | **Kubernetes (on DigitalOcean)**  | Industry-standard orchestration to build portable, scalable, and resilient applications.                                  |
| **Deployment**  | **Helm**                          | Manages the complexity of Kubernetes deployments, enabling reproducible, one-command application installation.        |
| **Database**    | **Neon (Postgres + TimescaleDB)** | A serverless, managed database simplifies operations and reduces cost. TimescaleDB provides powerful time-series analytics. |
| **Messaging**   | **CloudAMQP (RabbitMQ)**          | A managed message queue to create a resilient, asynchronous pipeline, ensuring data is not lost if a worker fails. |
| **Backend**     | **Python & FastAPI**              | High-performance async framework ideal for building robust, well-documented APIs with built-in data validation.      |
| **Observability**| **Grafana Cloud & Prometheus**    | Production-grade, cloud-native monitoring to track both system health and the key economic indicators Fathom produces. |
| **CI/CD**       | **GitHub Actions**                | Automates testing, container image builds, and deployments, ensuring a reliable and professional development workflow. |


### Project Status

**Alpha / In Development.** The core architecture is defined, and implementation of the data pipeline is underway.

### 7. License
This project is licensed under the **GNU General Public License v3.0**. See the `LICENSE` file for details.```
