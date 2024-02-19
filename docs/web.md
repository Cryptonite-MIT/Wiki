# Web Exploitation Wiki

## Overview of Web Application Security
Web Application Security is a specialized area within Information Security that focuses on safeguarding websites, web applications, and web services. It leverages application security principles specifically for the web, ensuring the integrity, confidentiality, and availability of web applications.

## Understanding Security Threats
A security threat is a potential risk that could exploit vulnerabilities in a computer system, leading to unauthorized access or damage. These threats can be intentional, such as cyber-attacks, or accidental, such as system failures or natural disasters.

### Common Security Threats

- **Virus Threats**: Viruses are malicious software programs designed to infect legitimate software, corrupt data, and modify the way applications operate without the user's consent.

- **Hackers and Predators**: The human element behind threats, hackers use their technical expertise to bypass security measures and gain unauthorized access to computer systems.

- **Phishing**: A technique used to deceive users into providing sensitive information by masquerading as a trustworthy entity in digital communication.

### The OWASP Top 10 Vulnerabilities
The Open Web Application Security Project (OWASP) identifies the most critical web application security risks. Key vulnerabilities include Injection, Broken Authentication, Sensitive Data Exposure, XML External Entities (XXE), Broken Access Control, Security Misconfiguration, Cross-Site Scripting (XSS), Insecure Deserialization, Using Components with Known Vulnerabilities, and Insufficient Logging & Monitoring.

## Web Development and Security Tools

### Client-Side Technologies
- **HTML**: The standard markup language for creating web pages.
- **JavaScript**: A programming language that enables interactive web pages.
- **CSS**: A style sheet language used for describing the presentation of a document written in HTML or XML.
- **jQuery**: A fast, small, and feature-rich JavaScript library.

### Server-Side Languages
- **PHP**
- **JavaScript (Node.js)**
- **Ruby**
- **Python**

### Important Web Mechanisms
- **Cookies and Sessions**: Essential for managing user sessions and storing user preferences.
- **HTTP Headers and Requests**: Fundamental components of the HTTP protocol that facilitate client-server communication.
- **HTTP Methods**: GET, POST, PUT, DELETE, CONNECT, HEAD, OPTIONS, TRACE, PATCH, each serving a specific purpose in HTTP transactions.

### Developer Tools
Modern browsers include developer tools for debugging and testing web applications, offering features like JavaScript debugging, network analysis, and DOM manipulation.

## Vulnerabilities and Exploits

### File Upload Vulnerabilities
Improper handling of file uploads can lead to unauthorized access or code execution on the server.

### Local File Inclusion (LFI)
Allows attackers to include files on a server through the web browser, potentially leading to code execution or data leakage.

### SQL Injection
A vulnerability that allows attackers to execute malicious SQL code, potentially accessing or modifying data in the database.

### OS Command Injection
Occurs when web applications execute system commands with user-supplied input, potentially leading to full system compromise.

### Cross-Site Scripting (XSS)
A vulnerability where attackers inject malicious scripts into web pages viewed by other users, leading to data theft or session hijacking.

### Same Origin Policy (SOP)
A security measure that restricts how a document or script from one origin can interact with resources from another origin, crucial for preventing malicious document access.

## Conclusion
This wiki serves as a comprehensive guide to understanding and mitigating web application vulnerabilities. By adhering to security best practices and staying informed about potential threats, developers and security professionals can safeguard web applications against exploitation.
