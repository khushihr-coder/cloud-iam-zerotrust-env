# Cloud-IAM-ZeroTrust-Env

An OpenEnv reinforcement learning (RL) environment where an AI agent receives an over-permissive AWS IAM policy along with an audit log of actual API calls, and must rewrite the policy to enforce **least-privilege access** without breaking application functionality.

---

## 🚀 Environment Description

In real-world cloud systems, developers often deploy overly permissive IAM policies such as:

```json
{ "Action": "s3:*", "Resource": "*" }
```

This allows unrestricted access, making systems vulnerable to data breaches.

This environment simulates that real-world problem and trains an AI agent to:

* Analyze existing IAM policies
* Compare them with actual usage (audit logs)
* Generate a secure, least-privilege policy

No real AWS infrastructure is required — everything is simulated in Python.

---

## 🎯 Objective

The agent must:

* Remove unnecessary permissions
* Retain only required actions and resources
* Ensure application functionality is not broken

---

## ⚙️ Action Space

| Action            | Reward / Cost         | Description                          |
| ----------------- | --------------------- | ------------------------------------ |
| AnalyzePolicy     | +0.10 (first use)     | Compares policy with audit log       |
| TestPolicy        | -0.05 / -0.10 / -0.20 | Simulates API calls (max 3 uses)     |
| SubmitFinalPolicy | 0.0 – 1.0             | Ends episode and triggers evaluation |

---

## 📊 Observation Space

| Field              | Type         | Description                   |
| ------------------ | ------------ | ----------------------------- |
| task_description   | string       | Task objective                |
| audit_log          | list[string] | Actual API calls made         |
| current_policy     | string       | Current IAM policy            |
| simulator_feedback | string       | Feedback from previous action |
| test_calls_used    | int          | Number of test calls used     |
| done               | boolean      | Whether task is complete      |
| reward             | float        | Reward from last action       |

---

## 🧪 Tasks

| Task ID | Difficulty | Description                       |
| ------- | ---------- | --------------------------------- |
| easy    | Easy       | Restrict S3 wildcard access       |
| medium  | Medium     | Handle DynamoDB + SQS permissions |
| hard    | Hard       | Cross-account IAM trust policy    |

---

## 📈 Baseline Scores

(⚠️ Run inference.py and fill these values)

| Task   | Score | Steps |
| ------ | ----- | ----- |
| easy   | TBD   | TBD   |
| medium | TBD   | TBD   |
| hard   | TBD   | TBD   |

---

## 🛠️ Setup Instructions

Install dependencies:

```bash
pip install openenv-core pydantic openai fastapi uvicorn
```

Run the server:

```bash
python server.py
```

---

## 🧪 API Testing

Test reset endpoint:

```bash
curl -X POST http://localhost:7860/reset \
 -H "Content-Type: application/json" \
 -d "{}"
```

Health check:

```bash
curl http://localhost:7860/health
```

---

## 🤖 Run Inference

Set environment variables:

```bash
export HF_TOKEN=your_token
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
export API_BASE_URL=https://router.huggingface.co/v1
```

Run tasks:

```bash
TASK_ID=easy python inference.py
TASK_ID=medium python inference.py
TASK_ID=hard python inference.py
```

---

## 🐳 Docker Setup

Build Docker image:

```bash
docker build -t iam-env .
```

Run container:

```bash
docker run -p 7860:7860 iam-env
```

---

## 🌐 Deployment

This project is deployed using Hugging Face Spaces with Docker support.

Ensure:

* `/reset` endpoint returns HTTP 200
* `/health` returns healthy status

---

## 🧠 Key Features

* Real-world IAM security problem
* Deterministic grading system
* Multi-task RL environment
* Fully containerized (Docker)
* OpenEnv compliant

---

## 👩‍💻 Team

* Khushi Rathod
* Samidha
* Disha

---

## 📌 Notes

* All required files are in root directory
* Environment follows OpenEnv specification
* Designed for real-world cloud security use cases

---

## 🏁 Conclusion

This environment demonstrates how AI can solve critical cloud security problems by enforcing least-privilege access, making systems safer and more reliable.
