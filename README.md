# Aegis AI WAF

Aegis is an advanced AI-powered Web Application Firewall (WAF) designed to protect large language models (LLMs) and their applications from sophisticated attacks such as prompt injection, jailbreaking, and adversarial instructions. It employs a multi-layered, tiered AI reasoning architecture to efficiently classify and neutralize threats while minimizing latency for legitimate requests.

## How It Works

Aegis operates on a principle of "fast pass-through for safe prompts, deeper AI reasoning for suspicious ones." This is achieved through a sophisticated, multi-layered processing pipeline:

1.  **Layer 1: Fast Scanner**
    *   Performs rapid, deterministic checks using regular expressions (`pyre2`, optionally `Hyperscan`) and heuristics to identify clear threats and allow safe prompts to bypass deeper analysis.
    *   **Goal:** Immediate blocking or fast-tracking in `~10ms`.

2.  **Layer 2: Intent Classifier (NeMo-based)**
    *   Utilizes a NeMo-based classifier (leveraging Llama Guard 3 logic) to assess the risk of a prompt and generate a `risk_score` (0-1).
    *   **Goal:** Provide a risk assessment within `~60ms`.

3.  **Tiered Routing**
    *   **Fast Track (`risk_score < 0.30`):** Prompts are allowed with minimal overhead.
    *   **Light CAMEL Verification (`0.30 - 0.70`):** Medium-risk prompts are escalated to a lighter CAMEL-AI agent verification process.
    *   **Full CAMEL Verification (`> 0.70`):** High-risk prompts undergo extensive analysis by multiple CAMEL-AI agents.

4.  **Layer 3: CAMEL Verification**
    *   A sophisticated multi-agent system built with `CAMEL-AI` where specialized agents (`Intent Analyst`, `Policy Auditor`, `Tool-Risk Auditor`, `Adversarial Simulator`, `Final Judge`) collaboratively reason and reach a consensus on complex prompts.

5.  **Layer 3.5: Output Validator**
    *   Intercepts AI-generated outputs *before* they execute tool calls or return to users.
    *   Performs tool call validation, response content scanning (e.g., for PII, credentials), and output schema enforcement to prevent dangerous AI responses.

6.  **Layer 4: Explainability Engine**
    *   For any non-allow decision (block or constrain), Aegis generates structured, human-readable explanations, detailing the attack type and reasoning behind the decision.

7.  **Layer 5: Adaptive Feedback Loop**
    *   Continuously learns from new attack patterns and feedback. Uses embeddings and novelty detection to identify emerging threats and update its models and rules dynamically.

8.  **Layer 6: Session Behavior Monitor**
    *   Operates in parallel to track multi-turn attacks, gradual privilege escalation, and anomalous session patterns across an entire user session.

### Key Features:
*   **Tiered AI Reasoning:** Optimizes latency by applying deeper analysis only when necessary.
*   **Adaptive Learning:** Automatically improves detection capabilities over time.
*   **Explainable Decisions:** Clear, actionable reasons for every block or constraint.
*   **Output Validation:** Guards against malicious AI-generated content and tool abuse.
*   **Multi-Turn Attack Detection:** Monitors session context to identify evolving threats.

## Prerequisites

To set up and run Aegis, you will need:

*   **Python 3.8+** (recommended)
*   **System Dependencies:**
    *   `Redis`: Used for asynchronous queues, caching, and session state tracking.
    *   `PostgreSQL`: For audit logs, feedback, and versioning of rules and models.
    *   NVIDIA NeMo Guardrails: The core framework for intent classification and policy enforcement.
*   **Python Libraries:**
    The following Python packages can be installed using `pip` from `requirements.txt`:
    *   `camel-ai`: Core framework for the multi-agent system.
    *   `openai`: For integrating with OpenAI-compatible LLMs (e.g., Llama 3.3 via NVIDIA NIM, Groq, Together).
    *   `nemoguardrails`: NVIDIA's framework for AI guardrails.
    *   `python-dotenv`: For managing environment variables (e.g., API keys).
    *   `pydantic`: For data validation and settings management.
    *   `httpx`: A modern HTTP client.
    *   `tenacity`: For retrying failed operations.
    *   `pyre2`: Python wrapper for Google's RE2 regex engine (for Layer 1 Fast Scanner).
    *   `python-hyperscan` (Optional): For accelerated large signature set matching in Layer 1.
    *   `FastAPI` & `Uvicorn`: For building the core API gateway.
    *   `Streamlit`: For the interactive frontend dashboard.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/aegis-waf.git
    cd aegis-waf
    ```
2.  **Set up a Python virtual environment:**
    ```bash
    python -m venv venv
    ./venv/Scripts/activate # On Windows
    # source venv/bin/activate # On Linux/macOS
    ```
3.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Install System Dependencies:**
    Ensure `Redis` and `PostgreSQL` are installed and running on your system, or accessible via Docker/cloud services. Configure their connection details in your environment variables.
5.  **Environment Variables:**
    Create a `.env` file in the root directory (refer to `.env.example` if available) and populate it with necessary API keys (e.g., NVIDIA, Google) and database connection strings.
    ```
    # .env example
    NVIDIA_API_KEY=your_nvidia_api_key
    GOOGLE_API_KEY=your_google_api_key
    DATABASE_URL=postgresql://user:password@host:port/database
    REDIS_URL=redis://localhost:6379/0
    ```

## Usage

### Running the Core WAF Gateway

The core WAF API gateway is built with FastAPI.
```bash
uvicorn core.gateway:app --host 0.0.0.0 --port 8000
```
This will start the WAF, making its `evaluate` and `feedback` APIs available (e.g., at `http://localhost:8000/v1/waf/evaluate`).

### Running the Frontend Dashboard

The interactive dashboard provides a visual interface for monitoring WAF decisions, metrics, and explanations.
```bash
streamlit run frontend/app.py
```
This will open the dashboard in your web browser, typically at `http://localhost:8501`.

### Running Tests

To verify the WAF's functionality and performance:
```bash
pytest tests/
```
This will execute the automated benchmarks and tests.

---

**Note:** This `README.md` provides a high-level overview. For detailed configuration, agent customization, and advanced deployment strategies, please refer to the specific documentation within the `config/` and `agents/` directories.
