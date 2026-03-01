# ec2-ops-ai-agent#

## Short Description
An AI-powered **EC2 & Auto Scaling operations agent** built using **Amazon Bedrock** and **AWS Lambda**.  
This project focuses on **safe, approval-based EC2 and ASG management** using a strict OpenAPI-driven action model. 

## Overview
`ec2-ops-ai-agent` is a learning and experimentation project created to understand how **Amazon Bedrock Agents** can be used for real-world cloud operations.

The agent can interpret user intent (for example: start/stop EC2, manage ASGs) and map it to controlled AWS operations executed via a Lambda backend.

At this stage:
- ✅ Bedrock Agent + Lambda backend is implemented
- ✅ OpenAPI schema–based action validation is implemented
---

## Key Features
- **Approval-based execution**  
  All resource-changing operations require explicit confirmation (`Type APPROVE to proceed`).

- **Strict OpenAPI compliance**  
  The agent can only use actions and parameters defined in the OpenAPI schema.

- **EC2 Operations Supported**
  - Describe, start, stop, terminate instances  
  - Create instances (free-tier–safe defaults)  
  - AMI, snapshot, volume, security group, key pair, EIP operations

- **Auto Scaling Group (ASG) Operations Supported**
  - Describe, create, update, and delete ASGs  
  - Suspend/resume processes  
  - Instance scale-in protection

- **Beginner-friendly responses**  
  Each action returns a short explanation of what it does and why it may fail.

---
## Architecture (Current)
```
User → Amazon Bedrock Agent
          ↓
   Action Group (OpenAPI)
          ↓
     AWS Lambda
          ↓
   AWS EC2 / ASG APIs
```

## Repository Structure
```
.
├── lambda/
│   └── ec2_asg_agent_lambda.py
├── openapi/
│   └── ec2-ops-openapi.yaml
├── docs/
│   └── Agent-Instructions.docx
└── README.md
```
## Next Planned Enhancements
- Add **API Gateway (REST API)**
- Separate EC2 and ASG action groups cleanly
- Improve error classification and remediation hints
- Add architecture diagram
---

