# Final Project Proposal

## Project Title

**AI-Assisted Cryptographic Auditing and Post-Quantum Cryptography Migration Framework**

---

## 1. Project Overview

This final project proposes an AI-assisted framework for detecting quantum-vulnerable cryptographic usage in software projects and providing practical Post-Quantum Cryptography (PQC) migration recommendations.

Many modern software systems still rely on classical public-key cryptographic algorithms such as RSA, ECC, and Diffie-Hellman. These algorithms are currently secure against classical computers because they are based on mathematical problems that are computationally infeasible to solve efficiently with traditional hardware. However, with the development of quantum computing, these assumptions may no longer hold in the future.

The goal of this project is to design a hybrid security analysis pipeline that combines **static code analysis** and **AI semantic auditing**. The system will scan source code repositories, extract cryptographic patterns, identify quantum-vulnerable implementations, assess their risk level, and generate migration suggestions toward post-quantum alternatives.

---

## 2. Motivation

Many modern systems still rely on classical cryptographic algorithms such as RSA and ECC.

However, quantum computing and complicated cryptographic usage make manual security auditing difficult and expensive. In real-world software projects, cryptographic functions are often scattered across source code, configuration files, TLS settings, certificate handling logic, and third-party library calls. This makes it difficult for developers and security engineers to manually inspect every security-sensitive component.

Therefore, we propose an AI-assisted framework for:

- **Quantum risk detection**
- **Cryptographic auditing**
- **PQC migration recommendation**

The main motivation of this project is to reduce the cost and complexity of cryptographic security auditing while helping developers understand which parts of their codebase may become insecure in the post-quantum era.

---

## 3. Technical Background

The industry currently relies on asymmetric encryption protocols such as **RSA**, **ECC**, and **Diffie-Hellman**. These protocols are widely used in TLS, digital signatures, authentication systems, secure communication, and certificate-based security mechanisms.

For classical computers, breaking these algorithms is considered practically infeasible because they rely on hard mathematical problems such as:

- Integer factorization, which is the foundation of RSA security.
- Discrete logarithm problems, which are used in Diffie-Hellman and ECC-based systems.
- Elliptic curve discrete logarithm problems, which are used in modern ECC-based cryptography.

However, with the advancement of quantum hardware, **Shor's Algorithm** has been proven capable of solving integer factorization and discrete logarithm problems in polynomial time on a sufficiently powerful quantum computer. This means that many widely deployed public-key cryptographic systems may become insecure once large-scale fault-tolerant quantum computers become practical.

At the same time, large-scale software systems often use cryptography in complex ways. Cryptographic APIs may be wrapped inside helper functions, hidden inside dependencies, or configured through files rather than explicit source code. As a result, simple keyword search is not enough to understand whether a system is truly quantum-safe.

Integrating AI into the auditing workflow can help replace time-consuming manual reviews. Large language models can analyze code context, interpret cryptographic usage, and help identify vulnerable patterns that are difficult to detect using simple rule-based tools alone.

---

## 4. Problem Statement

This project focuses on the following problems:

1. **Legacy cryptographic algorithms are difficult to locate.**  
   Algorithms such as RSA, ECC, and Diffie-Hellman may be hidden across large-scale codebases, libraries, configuration files, and certificate handling logic.

2. **Traditional public-key cryptography may become vulnerable.**  
   As quantum computing continues to develop, currently secure public-key cryptographic systems may become vulnerable to quantum attacks.

3. **Manual cryptographic auditing is not scalable.**  
   Reviewing large repositories manually is time-consuming, error-prone, and difficult to repeat consistently across many projects.

4. **Developers lack clear PQC migration guidance.**  
   Even if vulnerable cryptographic usage is detected, developers may not know which post-quantum alternatives are appropriate or how to migrate existing systems safely.

The project therefore aims to build a framework that can automatically detect quantum-vulnerable cryptographic usage and provide actionable security recommendations.

---

## 5. System Pipeline

The proposed system follows a seven-stage pipeline.

![System Pipeline](image(58).png)

### 5.1 Source Code Repository

The input of the system is a source code repository. The repository may come from:

- GitHub projects
- Local software projects
- Open-source repositories
- Security-sensitive application codebases

The framework will scan the repository to find files that may contain cryptographic usage, security configurations, or TLS-related logic.

### 5.2 Static Code Scanner

The first analysis stage uses static code scanning to identify possible cryptographic usage. This component searches for cryptographic APIs, TLS settings, certificate handling logic, and security-related dependencies.

Possible targets include:

- OpenSSL function calls
- Java Cryptography Architecture APIs
- Python cryptographic libraries
- TLS configuration files
- Certificate loading and verification logic
- Hard-coded algorithm names such as RSA, ECC, ECDSA, ECDH, DH, SHA, AES, and related identifiers

This stage acts as a filtering layer. It reduces the amount of code that needs to be sent to the AI model, which improves efficiency and lowers cost.

### 5.3 Cryptographic Pattern Extraction

After the static scanner finds candidate code blocks, the system extracts and normalizes cryptographic patterns.

This step may include:

- Extracting relevant code snippets.
- Recording file names and line numbers.
- Identifying algorithm names.
- Identifying library or API usage.
- Normalizing different API styles into a common representation.
- Grouping related code blocks by function, class, module, or configuration file.

The purpose of this stage is to transform raw source code into structured cryptographic evidence that can be further analyzed by the AI semantic analysis module.

### 5.4 AI Semantic Analysis

The AI semantic analysis stage uses large language models to understand the code context.

Instead of only detecting whether a keyword appears, the LLM analyzes how the cryptographic algorithm is being used. For example, it can distinguish between:

- Code that actively uses RSA for encryption or signing.
- Code that only mentions RSA in comments or documentation.
- Code that configures TLS with an outdated key exchange method.
- Code that loads certificates but does not directly implement cryptography.
- Wrapper functions that indirectly call vulnerable cryptographic APIs.

This stage helps the framework identify insecure cryptographic usage more accurately than a purely rule-based scanner.

### 5.5 Quantum Risk Assessment

After the AI model understands the cryptographic usage, the system classifies each detected algorithm or code block into a risk category.

Possible categories include:

- **Quantum-safe**: The usage is not known to be vulnerable to quantum attacks, or it already uses post-quantum cryptography.
- **Partially vulnerable**: The usage may be vulnerable depending on context, key size, protocol version, or deployment scenario.
- **Quantum-vulnerable**: The usage relies on algorithms such as RSA, ECC, ECDSA, ECDH, or Diffie-Hellman, which are vulnerable to sufficiently powerful quantum attacks.

The system may also generate a risk score based on:

- Algorithm type
- Key size
- Usage context
- Whether the algorithm protects long-term secrets
- Whether the usage appears in authentication, TLS, key exchange, or digital signatures
- Whether the code is part of production logic or testing logic

### 5.6 PQC Migration Suggestion

After risk assessment, the framework generates PQC migration suggestions.

The suggestions may include:

- Replacing quantum-vulnerable public-key algorithms with post-quantum alternatives.
- Recommending hybrid migration strategies.
- Suggesting candidate PQC algorithms for key encapsulation or digital signatures.
- Explaining compatibility concerns.
- Providing developer-friendly refactoring guidance.
- Warning about cases where direct replacement is unsafe or requires protocol-level redesign.

The goal of this stage is not only to report vulnerabilities but also to help developers understand what they should do next.

### 5.7 Final Security Report

The final output of the framework is a security report.

The report will include:

- Detected cryptographic usage.
- File names and line numbers.
- Identified algorithms and libraries.
- Quantum risk classification.
- Risk score.
- Explanation of why the usage may be vulnerable.
- Recommended PQC migration strategies.
- Summary of high-risk areas in the repository.

This report is intended to help developers, security engineers, and project maintainers prioritize migration work.

---

## 6. Methodology

The methodology of this project is based on a hybrid framework combining static analysis and AI-based semantic understanding.

### 6.1 Detect Cryptographic APIs and Configurations

The system first detects cryptographic APIs, TLS settings, and certificate handling logic in common libraries and languages, such as:

- OpenSSL
- Java Cryptography Architecture
- Python crypto libraries
- TLS-related configuration files

This stage identifies possible cryptographic usage before deeper analysis.

### 6.2 Use LLMs for Code Understanding

After candidate snippets are extracted, large language models are used to:

- Understand code context.
- Identify whether the code is actually using cryptography.
- Detect insecure or quantum-vulnerable cryptographic usage.
- Explain why the usage may be risky.
- Distinguish real implementation code from comments, examples, or test-only code.

### 6.3 Classify Cryptographic Risk

The framework classifies detected cryptographic algorithms into three major categories:

- **Quantum-safe**
- **Partially vulnerable**
- **Quantum-vulnerable**

This classification helps the system generate structured and understandable risk analysis.

### 6.4 Generate PQC Recommendations

Finally, the system generates PQC recommendations, including:

- Possible PQC replacements.
- Migration strategies.
- Compatibility considerations.
- Suggested developer actions.
- Security report summaries.

---

## 7. Expected Implementation

### 7.1 Core Strategy

The core strategy of this project is a **hybrid framework**:

> Static Analysis + AI Semantic Auditing

Static analysis is used for fast and scalable filtering, while AI semantic auditing is used for deeper contextual understanding.

### 7.2 Phase 1: Rule-Based Filtering

The first implementation phase uses tools such as **Semgrep** or regular expressions to isolate cryptographic code blocks.

This phase may detect patterns such as:

- `RSA_generate_key`
- `EVP_PKEY_RSA`
- `EC_KEY_new`
- `ECDSA_sign`
- `ECDH_compute_key`
- `KeyPairGenerator.getInstance("RSA")`
- `KeyPairGenerator.getInstance("EC")`
- `Cipher.getInstance("RSA")`
- Python library calls involving RSA, ECC, or TLS configuration

The main purpose of this phase is to reduce the amount of irrelevant code and lower the cost of AI analysis.

### 7.3 Phase 2: AI Semantic Auditing

The second phase sends selected code snippets to an LLM for deeper analysis.

The LLM will be asked to identify:

- What cryptographic algorithm is used.
- Whether the usage is security-sensitive.
- Whether the usage is quantum-vulnerable.
- Whether the code is part of production logic, testing, or documentation.
- What risks may exist.
- What migration suggestions are appropriate.

This phase provides more accurate analysis than rule-based scanning alone.

### 7.4 Phase 3: PQC Migration Engine

The third phase generates PQC migration guidance.

The migration engine will produce:

- Candidate PQC alternatives.
- Practical refactoring suggestions.
- Compatibility warnings.
- Risk explanations.
- Final report entries.

This component turns detection results into actionable recommendations.

---

## 8. Expected Results

The project is expected to produce the following outcomes:

### 8.1 Automated Detection of Legacy Cryptography

The AI model will identify outdated cryptographic implementations within large codebases.

Expected detected targets include:

- RSA usage
- ECC usage
- ECDSA signatures
- ECDH key exchange
- Diffie-Hellman key exchange
- TLS configurations using quantum-vulnerable public-key cryptography

### 8.2 Quantum Vulnerability Identification

The system is expected to flag specific lines of code and dependencies that may be vulnerable to quantum attacks.

For each detected case, the system should explain:

- Which algorithm is used.
- Where it appears in the repository.
- Why it may be quantum-vulnerable.
- Whether the risk is direct, indirect, or context-dependent.

### 8.3 Actionable PQC Migration Recommendations

The tool will generate concrete and practical migration suggestions.

Examples of recommendations include:

- Consider post-quantum key encapsulation mechanisms for key exchange.
- Consider post-quantum digital signature schemes for authentication.
- Use hybrid classical and post-quantum migration strategies when compatibility is required.
- Avoid directly replacing cryptographic primitives without considering protocol-level requirements.

### 8.4 Reduction in Manual Auditing Costs

The automated pipeline will significantly reduce the time and human effort traditionally required for massive cryptographic security audits.

Instead of manually reviewing an entire repository, developers can focus on high-risk code blocks identified by the framework.

---

## 9. Future Work

### 9.1 Support for More Cryptographic Algorithms

The framework will expand its analysis capability to support additional cryptographic algorithms, protocols, and security libraries.

Future targets may include:

- More TLS implementations
- Additional language-specific crypto libraries
- Certificate management tools
- Key management systems
- Hybrid cryptographic protocols

### 9.2 CI/CD Security Integration

The system will be integrated into CI/CD pipelines for automated real-time cryptographic security scanning during software development.

Possible integration targets include:

- GitHub Actions
- GitLab CI
- Jenkins
- Pre-commit hooks
- Pull request security checks

This would allow the framework to detect risky cryptographic usage before vulnerable code is merged into production branches.

### 9.3 Automatic Secure Refactoring

The framework may generate more advanced AI-assisted code modification and secure PQC migration suggestions.

Future versions could provide:

- Patch suggestions.
- Refactoring templates.
- API replacement guidance.
- Migration checklists.
- Developer-facing warnings and explanations.

### 9.4 Large-Scale Repository Analysis

The tool will be evaluated on larger open-source and enterprise-scale repositories to improve scalability and robustness.

This evaluation may help measure:

- Detection accuracy.
- False positive rate.
- False negative rate.
- Analysis time.
- AI cost.
- Usefulness of generated migration recommendations.

---

## 10. Project Deliverables

The expected deliverables of this final project are:

1. **Static code scanner prototype**  
   A scanner that detects cryptographic API usage and TLS-related patterns.

2. **Cryptographic pattern extraction module**  
   A module that extracts file paths, line numbers, algorithm names, and relevant code snippets.

3. **AI semantic analysis module**  
   A prompt-based or API-based LLM component that analyzes code context and classifies cryptographic usage.

4. **Quantum risk assessment module**  
   A rule-based or AI-assisted module that assigns risk categories and risk scores.

5. **PQC migration recommendation module**  
   A module that generates practical migration suggestions.

6. **Final security report generator**  
   A report generator that summarizes findings and recommendations in a developer-friendly format.

7. **Final presentation and project documentation**  
   A clear explanation of motivation, background, methodology, implementation, expected results, and future work.

---

## 11. Possible System Input and Output

### 11.1 Example Input

The system may take a GitHub or local repository as input:

```text
Input:
- GitHub repository URL
- Local project directory
- Source code files
- Configuration files
```

### 11.2 Example Output

The system may generate a report similar to the following:

```text
File: src/security/key_exchange.py
Line: 42
Detected Algorithm: ECDH
Risk Level: Quantum-vulnerable
Reason: ECDH relies on the elliptic curve discrete logarithm problem, which is vulnerable to Shor's Algorithm on sufficiently powerful quantum computers.
Recommendation: Consider using a post-quantum key encapsulation mechanism or a hybrid key exchange strategy.
```

---

## 12. Conclusion

This project proposes an AI-assisted cryptographic auditing framework for detecting quantum-vulnerable cryptographic usage and generating post-quantum migration recommendations.

The key idea is to combine the scalability of static analysis with the contextual understanding of large language models. Static analysis quickly identifies suspicious cryptographic patterns, while AI semantic analysis determines whether the detected code is actually security-sensitive and quantum-vulnerable.

The final system is expected to help developers reduce manual auditing effort, identify risky legacy cryptography, and receive practical guidance for transitioning toward post-quantum cryptography.
