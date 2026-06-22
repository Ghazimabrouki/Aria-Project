# SOC Project - Mermaid Diagram Library

All diagrams use a light theme and are intended for insertion into the presentation or report.

## Phase 1 - Security Monitoring Foundation

### Diagram 1 - Global Architecture & Data Flow
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart TB
  TITLE["Phase 1 - Global Architecture & Data Flow<br/><span style='font-size:14px;color:#2563EB'>Security Monitoring Foundation</span>"]
  TITLE --> ARCH
  subgraph ARCH["End-to-End Monitoring Architecture"]
    direction LR
    subgraph SOURCES["1. Security & Monitoring Sources"]
      direction TB
      SYS["System Logs<br/>OS activity"]
      AUTH["Authentication Logs<br/>SSH / login / access events"]
      SUR["Suricata<br/>Network IDS"]
      WAZ["Wazuh<br/>Host / Endpoint Security"]
      FAL["Falco<br/>Runtime / Container Security"]
      TEG["Telegraf<br/>System Metrics"]
    end
    subgraph FORWARD["2. Collection & Forwarding Layer"]
      direction TB
      FB["Filebeat<br/>Reads and ships logs"]
      FSK["Falcosidekick<br/>Receives and forwards Falco alerts"]
    end
    subgraph CORE["3. SIEM Core"]
      direction TB
      ES["Elasticsearch<br/>Central Storage<br/>Search<br/>Indexing"]
      KB["Kibana<br/>Dashboards<br/>Monitoring<br/>Analysis"]
    end
  end
  SYS -->|"system logs"| FB
  AUTH -->|"auth logs"| FB
  SUR -->|"eve.json events"| FB
  WAZ -->|"host alerts"| FB
  FAL -->|"runtime alerts"| FSK
  FB -->|"logs + alerts"| ES
  FSK -->|"falco-events"| ES
  TEG -->|"metrics"| ES
  ES -->|"indexed data"| KB
  KB --> OUTCOME["Unified Monitoring View<br/>Logs, alerts, runtime events, and metrics are centralized and ready for analysis."]
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef source fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef forward fill:#ECFDF5,stroke:#16A34A,stroke-width:1.5px,color:#0F172A;
  classDef core fill:#FFF7ED,stroke:#EA580C,stroke-width:1.5px,color:#0F172A;
  classDef outcome fill:#FEF3C7,stroke:#D97706,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class SYS,AUTH,SUR,WAZ,FAL,TEG source;
  class FB,FSK forward;
  class ES,KB core;
  class OUTCOME outcome;
  style ARCH fill:#FFFFFF,stroke:#94A3B8,stroke-width:1.5px,color:#0F172A
  style SOURCES fill:#EFF6FF,stroke:#2563EB,stroke-width:2px,color:#0F172A
  style FORWARD fill:#ECFDF5,stroke:#16A34A,stroke-width:2px,color:#0F172A
  style CORE fill:#FFF7ED,stroke:#EA580C,stroke-width:2px,color:#0F172A
```

### Diagram 2 - Deployment, Technical Setup & Requirements
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart TB
  subgraph TOP["Deployment Context"]
    direction LR
    subgraph EXT["External Access & Inputs"]
      direction TB
      AGT["Wazuh Agents<br/>/ Endpoints"]
      USER["SOC Analyst"]
    end
    subgraph REF["Technical Reference"]
      direction LR
      subgraph CONFIG["Main Configuration Files"]
        direction TB
        C1["Elasticsearch<br/>/etc/elasticsearch/*"]
        C2["Kibana<br/>/etc/kibana/kibana.yml"]
        C3["Filebeat<br/>/etc/filebeat/filebeat.yml<br/>/etc/filebeat/modules.d/*"]
        C4["Suricata<br/>/etc/suricata/suricata.yaml"]
        C5["Wazuh<br/>/var/ossec/*"]
        C6["Falco / Falcosidekick<br/>docker-compose.yml / .env"]
        C7["Telegraf<br/>/etc/telegraf/telegraf.conf"]
      end
      subgraph REQ["Hardware Requirements"]
        direction TB
        R1["Minimum Lab Setup<br/>CPU: 4 cores<br/>RAM: 8 GB<br/>Disk: 50 GB"]
        R2["Recommended Setup<br/>CPU: 8 cores<br/>RAM: 16 GB<br/>Disk: 100 GB"]
        R3["OS Requirement<br/>Ubuntu 20.04+<br/>Internet connectivity required"]
      end
    end
  end
  subgraph HOST["Single Ubuntu Host"]
    direction LR
    subgraph SYSTEMD["Native / System Services"]
      direction TB
      ES["Elasticsearch<br/>9200 HTTPS"]
      KB["Kibana<br/>5601 HTTPS"]
      FB["Filebeat<br/>Log Shipper"]
      SUR["Suricata<br/>Network IDS"]
      WAZ["Wazuh Manager<br/>1514 Events<br/>1515 Registration"]
      TEG["Telegraf<br/>Metrics Agent"]
    end
    subgraph DOCKER["Docker Services"]
      direction TB
      FAL["Falco<br/>Runtime Detection"]
      FSK["Falcosidekick<br/>2801 HTTP"]
    end
  end
  TOP -->|"deployed and operated on"| HOST
  AGT -->|"1514 / 1515 TCP"| WAZ
  USER -->|"HTTPS 5601"| KB
  SUR -->|"eve.json"| FB
  WAZ -->|"alerts"| FB
  FB -->|"logs"| ES
  FAL -->|"runtime alerts"| FSK
  FSK -->|"falco-events"| ES
  TEG -->|"metrics"| ES
  ES -->|"dashboards data"| KB
  style TOP fill:#FFFFFF,stroke:#94A3B8,stroke-width:1.5px,color:#0F172A
  style EXT fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A
  style REF fill:#FFF7ED,stroke:#EA580C,stroke-width:1.5px,color:#0F172A
  style CONFIG fill:#FFFFFF,stroke:#EA580C,stroke-width:1px,color:#0F172A
  style REQ fill:#FFFFFF,stroke:#EA580C,stroke-width:1px,color:#0F172A
  style HOST fill:#EFF6FF,stroke:#1D4ED8,stroke-width:2px,color:#0F172A
  style SYSTEMD fill:#ECFDF5,stroke:#16A34A,stroke-width:1.5px,color:#0F172A
  style DOCKER fill:#F0FDFA,stroke:#0891B2,stroke-width:1.5px,color:#0F172A
```

### Diagram 3 - Visibility Layers & Tool Roles
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart TB
  TITLE["Phase 1 - Visibility Layers & Tool Roles<br/><span style='font-size:14px;color:#2563EB'>Monitoring every critical layer of the system</span>"]
  TITLE --> DOMAINS
  subgraph DOMAINS["Monitoring Coverage Domains"]
    direction LR
    subgraph NET_DOMAIN["Network Visibility"]
      direction TB
      NET["Network Layer<br/>Traffic, packets, protocols"]
      SUR["Suricata<br/>Network IDS"]
      SUR_ROLE["Detects scans, suspicious traffic,<br/>malicious flows, IDS alerts"]
      NET --> SUR --> SUR_ROLE
    end
    subgraph HOST_DOMAIN["Host Visibility"]
      direction TB
      HOST["Host / Endpoint Layer<br/>Auth, files, agents, processes"]
      WAZ["Wazuh<br/>Host / Endpoint Security"]
      WAZ_ROLE["Detects failed logins, file changes,<br/>host alerts, suspicious activity"]
      HOST --> WAZ --> WAZ_ROLE
    end
    subgraph RUN_DOMAIN["Runtime Visibility"]
      direction TB
      RUN["Runtime / Container Layer<br/>Processes, syscalls, containers"]
      FAL["Falco<br/>Runtime Security"]
      FAL_ROLE["Detects abnormal process behavior,<br/>container activity, suspicious syscalls"]
      RUN --> FAL --> FAL_ROLE
    end
    subgraph RES_DOMAIN["Resource Visibility"]
      direction TB
      RES["Resource / Infrastructure Layer<br/>CPU, RAM, disk, load, health"]
      TEG["Telegraf<br/>Metrics Agent"]
      TEG_ROLE["Collects system metrics,<br/>performance data, infrastructure health"]
      RES --> TEG --> TEG_ROLE
    end
  end
  DOMAINS --> PIPELINE
  subgraph PIPELINE["Collection, Centralization & Visualization"]
    direction LR
    FB["Filebeat<br/>Log Collection & Forwarding"]
    FSK["Falcosidekick<br/>Falco Alert Forwarding"]
    ES["Elasticsearch<br/>Central Storage, Search & Indexing"]
    KB["Kibana<br/>Dashboards, Monitoring & Analysis"]
    FB --> ES
    FSK --> ES
    ES --> KB
  end
  SUR_ROLE -->|"eve.json events"| FB
  WAZ_ROLE -->|"host alerts"| FB
  FAL_ROLE -->|"runtime alerts"| FSK
  TEG_ROLE -->|"metrics"| ES
  KB --> OUTCOME["Final Outcome of Phase 1<br/>Complete security monitoring foundation with global visibility across all critical layers."]
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef layer fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef tool fill:#ECFDF5,stroke:#16A34A,stroke-width:1.5px,color:#0F172A,font-weight:bold;
  classDef role fill:#FFFFFF,stroke:#94A3B8,stroke-width:1px,color:#0F172A;
  classDef core fill:#FFF7ED,stroke:#EA580C,stroke-width:1.5px,color:#0F172A,font-weight:bold;
  classDef outcome fill:#FEF3C7,stroke:#D97706,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class NET,HOST,RUN,RES layer;
  class SUR,WAZ,FAL,TEG,FB,FSK tool;
  class SUR_ROLE,WAZ_ROLE,FAL_ROLE,TEG_ROLE role;
  class ES,KB core;
  class OUTCOME outcome;
  style DOMAINS fill:#FFFFFF,stroke:#94A3B8,stroke-width:1.5px,color:#0F172A
  style NET_DOMAIN fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A
  style HOST_DOMAIN fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A
  style RUN_DOMAIN fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A
  style RES_DOMAIN fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A
  style PIPELINE fill:#FFF7ED,stroke:#EA580C,stroke-width:1.5px,color:#0F172A
```

## Phase 2 - Huawei Cloud Infrastructure

### Diagram 4 - Huawei Cloud Infrastructure Foundation
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart TB
  TITLE["Phase 2 - Huawei Cloud Infrastructure<br/><span style='font-size:14px;color:#2563EB'>Cloud foundation for hosting the SOC platform</span>"]
  TITLE --> CLOUD
  subgraph CLOUD["Huawei Cloud Environment"]
    direction LR
    subgraph NETWORK["Network & Access Layer"]
      direction TB
      VPC["VPC / Private Network<br/>Isolated cloud network"]
      SUBNET["Private Subnet<br/>Internal communication zone"]
      SG["Security Group<br/>Controlled firewall rules"]
      EIP["Elastic IP<br/>193.95.30.97"]
    end
    subgraph COMPUTE["Compute & Storage Layer"]
      direction TB
      VM["ECS Virtual Machine<br/><b>Ubuntu Server</b>"]
      RES["Allocated Resources<br/>64 vCPU · 128 GB RAM · 100 GB Storage"]
    end
  end
  subgraph PLATFORM["Hosted Platform"]
    direction TB
    STACK["SOC Monitoring Stack<br/>Elasticsearch · Kibana · Wazuh · Suricata<br/>Falco · Telegraf · Filebeat"]
  end
  SUBNET --> VM
  SG -->|"filters access"| VM
  EIP -->|"public access point"| VM
  VM --> RES
  RES --> STACK
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef cloud fill:#FFFFFF,stroke:#2563EB,stroke-width:2px,color:#0F172A;
  classDef network fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef compute fill:#ECFDF5,stroke:#16A34A,stroke-width:1.5px,color:#0F172A;
  classDef platform fill:#F5F3FF,stroke:#7C3AED,stroke-width:1.5px,color:#0F172A;
  class TITLE title;
  class CLOUD cloud;
  class NETWORK,VPC,SUBNET,SG,EIP network;
  class COMPUTE,VM,RES compute;
  class PLATFORM,STACK platform;
  style CLOUD fill:#FFFFFF,stroke:#2563EB,stroke-width:2px,color:#0F172A
  style NETWORK fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A
  style COMPUTE fill:#ECFDF5,stroke:#16A34A,stroke-width:1.5px,color:#0F172A
  style PLATFORM fill:#F5F3FF,stroke:#7C3AED,stroke-width:1.5px,color:#0F172A
```

## Phase 3 - Backend Intelligence Layer

### Diagram 5 - Global Phase 3 Backend Intelligence Layer
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart TB
  TITLE["Phase 3 - Backend Intelligence Layer<br/><span style='font-size:14px;color:#2563EB'>From raw monitoring data to SOC intelligence</span>"]
  ES["Elasticsearch<br/>Raw data from Wazuh, Suricata, Falco, Telegraf"]
  subgraph CORE["Core SOC Workflow"]
    direction LR
    ALERT["Alert Pipeline<br/>poll, map, dedup, filter, enrich"]
    INC["Incident Correlation<br/>group related alerts"]
    WATCH["Watcher & Investigations<br/>context, timeline, IOCs, risk"]
    AI["AI Response Engine<br/>summary, narrative, risk, playbook"]
    APPROVE["Approval & Execution<br/>guardrails, Ansible, verification"]
  end
  subgraph OPS["Operational Intelligence Modules"]
    direction LR
    PERF["Performance Monitoring<br/>metrics, anomalies, remediation"]
    IPS["IPS Map<br/>geo attacks, lifecycle, statistics"]
    ASSIST["AI Assistant<br/>SOC Q&A and actions"]
    OP["AI Operator<br/>NL-to-Ansible operations"]
  end
  UI["Frontend Dashboard<br/>alerts, incidents, investigations, metrics, IPS, assistant, operator"]
  TITLE --> ES
  ES --> ALERT --> INC --> WATCH --> AI --> APPROVE --> UI
  ES --> PERF --> UI
  ALERT --> IPS --> UI
  ASSIST --> UI
  OP --> UI
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2.5px,color:#0F172A,font-weight:bold;
  classDef input fill:#FFF7ED,stroke:#EA580C,stroke-width:1.5px,color:#0F172A;
  classDef core fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef ops fill:#F5F3FF,stroke:#7C3AED,stroke-width:1.5px,color:#0F172A;
  classDef ui fill:#ECFDF5,stroke:#16A34A,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class ES input;
  class ALERT,INC,WATCH,AI,APPROVE core;
  class PERF,IPS,ASSIST,OP ops;
  class UI ui;
  style CORE fill:#EFF6FF,stroke:#2563EB,stroke-width:2px,color:#0F172A
  style OPS fill:#F5F3FF,stroke:#7C3AED,stroke-width:2px,color:#0F172A
```

### Diagram 6 - Alert Ingestion & Enrichment Pipeline
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart LR
  TITLE["Step 1 - Alert Ingestion & Enrichment Pipeline"]
  ES["Elasticsearch<br/>wazuh-* · suricata-* · falco-* · filebeat-*"]
  POLL["Poller<br/>parallel polling<br/>cursor management"]
  MAP["Source Mappers<br/>Wazuh · Suricata · Falco · Filebeat · Generic"]
  DEDUP["Deduplication<br/>Redis + memory + DB"]
  FILTER["Filtering<br/>noise rules + severity threshold"]
  ENRICH["Enrichment<br/>GeoIP + MITRE + cloud provider"]
  CAMP["Campaign Tracking<br/>related alert grouping"]
  WHITE["Whitelist Check<br/>trusted IP / hash / domain"]
  STORE["SQLite Alert<br/>local persistence + _geo"]
  OUT["Visible in<br/>/alerts and /ips"]
  TITLE --> ES --> POLL --> MAP --> DEDUP --> FILTER --> ENRICH --> CAMP --> WHITE --> STORE --> OUT
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef input fill:#FFF7ED,stroke:#EA580C,stroke-width:1.5px,color:#0F172A;
  classDef process fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef enrich fill:#ECFDF5,stroke:#16A34A,stroke-width:1.5px,color:#0F172A;
  classDef output fill:#FEF3C7,stroke:#D97706,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class ES input;
  class POLL,MAP,DEDUP,FILTER,CAMP,WHITE process;
  class ENRICH enrich;
  class STORE,OUT output;
```

### Diagram 7 - Cursor-Based Elasticsearch Polling
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart LR
  TITLE["Step 1.1 - Cursor-Based Elasticsearch Polling"]
  subgraph ES["Elasticsearch Sources"]
    direction TB
    WZ["wazuh-alerts-*<br/>Wazuh"]
    FB["filebeat-* / suricata-*<br/>Filebeat + Suricata"]
    FC["falco-events-*<br/>Falco"]
    TG["telegraf-*<br/>Telegraf"]
  end
  subgraph POLL["Backend Polling Logic"]
    direction TB
    DISC["Source Discovery<br/>configured index patterns"]
    CUR["Cursor<br/>last processed timestamp"]
    QUERY["Query<br/>@timestamp > cursor"]
    SORT["Sort<br/>@timestamp ascending"]
    SEEN["Seen-ID Check<br/>skip processed ES _id"]
  end
  PROCESS["process_single_alert()<br/>send fresh document to pipeline"]
  TITLE --> ES
  WZ --> DISC
  FB --> DISC
  FC --> DISC
  TG --> DISC
  DISC --> CUR --> QUERY --> SORT --> SEEN --> PROCESS
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef source fill:#FFF7ED,stroke:#EA580C,stroke-width:1.5px,color:#0F172A;
  classDef poll fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef final fill:#ECFDF5,stroke:#16A34A,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class WZ,FB,FC,TG source;
  class DISC,CUR,QUERY,SORT,SEEN poll;
  class PROCESS final;
  style ES fill:#FFF7ED,stroke:#EA580C,stroke-width:2px,color:#0F172A
  style POLL fill:#EFF6FF,stroke:#2563EB,stroke-width:2px,color:#0F172A
```

### Diagram 8 - Raw Document to Clean SOC Alert
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart LR
  TITLE["Step 2 - Transform Raw Documents into Clean Alerts"]
  RAW["Raw ES Document<br/>source-specific format"]
  subgraph MAPPERS["Source-Specific Mappers"]
    direction TB
    WAZ["Wazuh Mapper"]
    SUR["Suricata Mapper"]
    FAL["Falco Mapper"]
    FB["Filebeat Mapper"]
    GEN["Generic Mapper"]
  end
  COMMON["Common Alert Model<br/>source, title, severity, category,<br/>source_ip, dest_ip, hostname, metadata"]
  PIPE["Alert Processing<br/>deduplication, filtering, enrichment,<br/>context, whitelist"]
  CLEAN["Clean SOC Alert<br/>ready for incident correlation"]
  TITLE --> RAW
  RAW --> MAPPERS
  MAPPERS --> COMMON
  COMMON --> PIPE
  PIPE --> CLEAN
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef raw fill:#FFF7ED,stroke:#EA580C,stroke-width:1.5px,color:#0F172A;
  classDef mapper fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef common fill:#ECFDF5,stroke:#16A34A,stroke-width:1.8px,color:#0F172A,font-weight:bold;
  classDef clean fill:#FEF3C7,stroke:#D97706,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class RAW raw;
  class WAZ,SUR,FAL,FB,GEN mapper;
  class COMMON common;
  class PIPE mapper;
  class CLEAN clean;
  style MAPPERS fill:#EFF6FF,stroke:#2563EB,stroke-width:2px,color:#0F172A
```

### Diagram 9 - Enrichment and Context Building
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart LR
  TITLE["Step 3 - Enrichment and Context Building"]
  ALERT["Normalized Alert"]
  GEO["GeoIP / ASN<br/>country, provider, location"]
  MITRE["MITRE ATT&CK<br/>tactics and techniques"]
  IOC["IOC Extraction<br/>IPs, domains, hashes, URLs"]
  CAMP["Campaign Detection<br/>repeated patterns, brute force,<br/>port scans, web attacks"]
  WHITE["Whitelist Check<br/>trusted IPs / hosts"]
  ENRICHED["Enriched Alert<br/>analyst-ready context"]
  TITLE --> ALERT
  ALERT --> GEO
  ALERT --> MITRE
  ALERT --> IOC
  GEO --> ENRICHED
  MITRE --> ENRICHED
  IOC --> ENRICHED
  ENRICHED --> CAMP --> WHITE
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef input fill:#ECFDF5,stroke:#16A34A,stroke-width:1.5px,color:#0F172A;
  classDef enrich fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef final fill:#FEF3C7,stroke:#D97706,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class ALERT input;
  class GEO,MITRE,IOC,CAMP,WHITE enrich;
  class ENRICHED final;
```

### Diagram 10 - Local Storage and SOC Data Model
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart TB
  TITLE["Step 4 - Local Storage and SOC Data Model"]
  DB["SQLite Local Database<br/>SOC workflow memory"]
  ALERT["Alert"]
  INC["Incident"]
  LINK["AlertIncidentLink"]
  INV["Investigation"]
  APPROVAL["PlaybookApproval"]
  RUN["PlaybookRun"]
  VERIFY["FixVerification"]
  ARCHIVE["Archive"]
  TITLE --> DB
  DB --> ALERT
  DB --> INC
  ALERT --> LINK
  INC --> LINK
  INC --> INV
  INV --> APPROVAL
  APPROVAL --> RUN
  RUN --> VERIFY
  VERIFY --> ARCHIVE
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef db fill:#FEF3C7,stroke:#D97706,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef table fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef action fill:#ECFDF5,stroke:#16A34A,stroke-width:1.5px,color:#0F172A;
  class TITLE title;
  class DB db;
  class ALERT,INC,LINK,INV table;
  class APPROVAL,RUN,VERIFY,ARCHIVE action;
```

### Diagram 11 - Incident Correlation
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart LR
  TITLE["Step 5 - Incident Correlation"]
  A1["Alert 1<br/>Wazuh SSH brute-force"]
  A2["Alert 2<br/>Suricata port scan"]
  A3["Alert 3<br/>Falco runtime event"]
  OBS["Observable Extraction<br/>IP, host, container, MITRE"]
  CORR["Correlation Engine<br/>time window + IOC + MITRE overlap"]
  INC["Incident<br/>single security case"]
  LINK["AlertIncidentLink<br/>correlation confidence"]
  TITLE --> A1
  TITLE --> A2
  TITLE --> A3
  A1 --> OBS
  A2 --> OBS
  A3 --> OBS
  OBS --> CORR --> INC --> LINK
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef alert fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef corr fill:#FEF3C7,stroke:#D97706,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef incident fill:#ECFDF5,stroke:#16A34A,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class A1,A2,A3 alert;
  class OBS,CORR corr;
  class INC,LINK incident;
```

### Diagram 12 - Watcher and Investigation Creation
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart TB
  TITLE["Step 6 - Watcher and Investigation Creation"]
  INC["Open Incident"]
  WATCH["Incident Watcher<br/>fast scan + full scan"]
  SKIP["Whitelist Check"]
  INV["Create Investigation<br/>status = pending"]
  CTX["Context Builder"]
  T1["Timeline"]
  T2["IOCs"]
  T3["MITRE"]
  T4["Behavioral Indicators"]
  T5["Auth Pattern"]
  T6["Risk Score"]
  AI["Trigger AI Engine"]
  TITLE --> INC
  INC --> WATCH --> SKIP --> INV --> CTX
  CTX --> T1
  CTX --> T2
  CTX --> T3
  CTX --> T4
  CTX --> T5
  CTX --> T6
  CTX --> AI
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef input fill:#ECFDF5,stroke:#16A34A,stroke-width:1.8px,color:#0F172A,font-weight:bold;
  classDef process fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef context fill:#FFFFFF,stroke:#94A3B8,stroke-width:1px,color:#0F172A;
  classDef final fill:#FEF3C7,stroke:#D97706,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class INC input;
  class WATCH,SKIP,INV,CTX process;
  class T1,T2,T3,T4,T5,T6 context;
  class AI final;
```

### Diagram 13 - AI Response Engine
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart LR
  TITLE["Step 7 - AI Response Engine"]
  CTX["Investigation Context<br/>timeline, IOCs, MITRE, risk"]
  CB["Circuit Breaker"]
  PROMPT["Prompt Builder<br/>strict sections"]
  LLM["LLM Provider<br/>Ollama / Gemini / OpenRouter / NIM"]
  PARSE["Parser<br/>SUMMARY / NARRATIVE / RISK / PLAYBOOK"]
  STORE["Store in Investigation"]
  APPROVE["Auto-Approve Check<br/>or human approval"]
  TITLE --> CTX
  CTX --> CB --> PROMPT --> LLM --> PARSE --> STORE --> APPROVE
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef input fill:#FEF3C7,stroke:#D97706,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef process fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef final fill:#ECFDF5,stroke:#16A34A,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class CTX input;
  class CB,PROMPT,LLM,PARSE,STORE process;
  class APPROVE final;
```

### Diagram 14 - Approval, Execution, Verification and Archive
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart LR
  TITLE["Step 8 - Approval, Execution, Verification and Archive"]
  PLAY["Generated Playbook"]
  APPROVAL["Approval Gate<br/>guardrails + confidence + human decision"]
  RUN["Ansible Execution<br/>SSH pre-check + ansible-playbook"]
  VERIFY["Fix Verification<br/>re-check alerts or metrics"]
  ARCHIVE["Archive<br/>preserve case history"]
  UI["Investigation UI"]
  TITLE --> PLAY
  PLAY --> APPROVAL --> RUN --> VERIFY --> ARCHIVE --> UI
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef input fill:#FEF3C7,stroke:#D97706,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef decision fill:#F5F3FF,stroke:#7C3AED,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef process fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef final fill:#ECFDF5,stroke:#16A34A,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class PLAY input;
  class APPROVAL decision;
  class RUN,VERIFY process;
  class ARCHIVE,UI final;
```

### Diagram 15 - Performance Monitoring and Remediation
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart LR
  TITLE["Step 9 - Performance Monitoring and Remediation"]
  TG["Elasticsearch<br/>telegraf-* metrics"]
  POLL["Performance Poller<br/>per-host metrics"]
  REDIS["Redis<br/>current metrics, history, baselines"]
  DETECT["Anomaly Detector<br/>threshold + baseline + cooldown"]
  RCA["Root Cause<br/>top process + playbook type"]
  INV["Performance Investigation"]
  PLAY["Dynamic Playbook"]
  EXEC["Approval + Ansible + Verification"]
  UI["/metrics Dashboard"]
  TITLE --> TG
  TG --> POLL --> REDIS --> DETECT --> RCA --> INV --> PLAY --> EXEC --> UI
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef input fill:#FFF7ED,stroke:#EA580C,stroke-width:1.5px,color:#0F172A;
  classDef process fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef storage fill:#F5F3FF,stroke:#7C3AED,stroke-width:1.5px,color:#0F172A;
  classDef final fill:#ECFDF5,stroke:#16A34A,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class TG input;
  class POLL,DETECT,RCA,INV,PLAY,EXEC process;
  class REDIS storage;
  class UI final;
```

### Diagram 16 - IPS Attack Visualization
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart LR
  TITLE["Step 10 - IPS Attack Visualization"]
  ALERT["Local SQLite Alerts<br/>+ upstream alerts"]
  DEDUP["Deduplicate<br/>source IP + time window"]
  GEO["GeoIP Resolve<br/>country, city, lat/lon, ASN"]
  CAT["Categorize<br/>brute-force, web attack,<br/>recon, malware, DoS, C2"]
  LIFE["Lifecycle<br/>active / investigating / mitigated / blocked"]
  MAP["/ips World Map<br/>paths, stats, live events"]
  TITLE --> ALERT
  ALERT --> DEDUP --> GEO --> CAT --> LIFE --> MAP
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef input fill:#FFF7ED,stroke:#EA580C,stroke-width:1.5px,color:#0F172A;
  classDef process fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef final fill:#ECFDF5,stroke:#16A34A,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class ALERT input;
  class DEDUP,GEO,CAT,LIFE process;
  class MAP final;
```

### Diagram 17 - Contextual AI Assistant
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart LR
  TITLE["Step 11 - Contextual AI Assistant"]
  Q["Analyst Question"]
  EXTRACT["Keyword Extraction<br/>IDs, IPs, hostnames, severity"]
  FETCH["Deep Entity Fetch<br/>alerts, incidents, investigations,<br/>archives, metrics, IPS, pipeline"]
  PROMPT["Context Prompt"]
  ANSWER["LLM or Fallback Answer"]
  ACTIONS["Suggested Actions"]
  STORE["Conversation Storage"]
  TITLE --> Q
  Q --> EXTRACT --> FETCH --> PROMPT --> ANSWER --> ACTIONS --> STORE
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef input fill:#FFF7ED,stroke:#EA580C,stroke-width:1.5px,color:#0F172A;
  classDef process fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef final fill:#ECFDF5,stroke:#16A34A,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class Q input;
  class EXTRACT,FETCH,PROMPT,ANSWER,ACTIONS process;
  class STORE final;
```

### Diagram 18 - AI Operator
```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#FFFFFF",
    "primaryTextColor": "#0F172A",
    "lineColor": "#475569",
    "fontFamily": "Inter, Arial"
  },
  "flowchart": {
    "useMaxWidth": true,
    "htmlLabels": true,
    "nodeSpacing": 35,
    "rankSpacing": 45,
    "curve": "basis"
  }
}}%%
flowchart LR
  TITLE["Step 12 - AI Operator"]
  REQ["Operator Request<br/>natural language"]
  REASON["Reasoning<br/>intent + confidence + tools"]
  TEMPLATE["Template Match<br/>or LLM playbook generation"]
  PENDING["OperatorRun<br/>pending"]
  GATE["Approval Gate<br/>auto for low-risk read-only<br/>manual for mutating actions"]
  EXEC["Ansible Execution"]
  ANALYSIS["Structured Result<br/>markdown analysis"]
  TITLE --> REQ
  REQ --> REASON --> TEMPLATE --> PENDING --> GATE --> EXEC --> ANALYSIS
  classDef title fill:#E0F2FE,stroke:#2563EB,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef input fill:#FFF7ED,stroke:#EA580C,stroke-width:1.5px,color:#0F172A;
  classDef process fill:#EFF6FF,stroke:#2563EB,stroke-width:1.5px,color:#0F172A;
  classDef decision fill:#F5F3FF,stroke:#7C3AED,stroke-width:2px,color:#0F172A,font-weight:bold;
  classDef final fill:#ECFDF5,stroke:#16A34A,stroke-width:2px,color:#0F172A,font-weight:bold;
  class TITLE title;
  class REQ input;
  class REASON,TEMPLATE,PENDING,EXEC process;
  class GATE decision;
  class ANALYSIS final;
```

