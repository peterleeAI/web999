// Quiz Database
const quizDatabase = {
    d1q1: {
        title: "Domain 1 Quiz 1: Security Fundamentals",
        questions: [
            {
                question: "Which of the following best describes the CIA triad in cybersecurity?",
                options: [
                    "Confidentiality, Integrity, and Availability",
                    "Control, Intelligence, and Analysis",
                    "Certification, Installation, and Authentication",
                    "Confidentiality, Identification, and Authorization"
                ],
                correct: 0,
                explanation: "The CIA triad stands for Confidentiality, Integrity, and Availability - the three fundamental goals of information security programs."
            },
            {
                question: "What is the primary purpose of the AAA framework?",
                options: [
                    "To encrypt data at rest and in transit",
                    "To manage identity and access by providing Authentication, Authorization, and Accounting",
                    "To monitor network traffic and detect anomalies",
                    "To provide secure remote access to systems"
                ],
                correct: 1,
                explanation: "AAA (Authentication, Authorization, and Accounting) is a framework that provides a comprehensive approach to managing user access and tracking activities."
            },
            {
                question: "In a DAC (Discretionary Access Control) model, who determines access rights?",
                options: [
                    "System administrators",
                    "Resource owners",
                    "Security officers",
                    "Government agencies"
                ],
                correct: 1,
                explanation: "In DAC, the resource owners have the discretion to determine who can access their resources, making it common in file systems."
            },
            {
                question: "Which access control model uses security clearance levels?",
                options: [
                    "DAC (Discretionary Access Control)",
                    "MAC (Mandatory Access Control)",
                    "RBAC (Role-Based Access Control)",
                    "ABAC (Attribute-Based Access Control)"
                ],
                correct: 1,
                explanation: "MAC enforces access policies based on security clearance levels, typically used in high-security environments like military systems."
            },
            {
                question: "What is a key principle of Zero Trust architecture?",
                options: [
                    "Trust but verify",
                    "Never trust, always verify",
                    "Trust all internal traffic",
                    "Verify only external connections"
                ],
                correct: 1,
                explanation: "Zero Trust follows the principle of 'never trust, always verify' - no user or system should be trusted by default, regardless of location."
            },
            {
                question: "Which cryptographic operation provides data integrity?",
                options: [
                    "Encryption",
                    "Hashing",
                    "Digital signatures",
                    "Both hashing and digital signatures"
                ],
                correct: 3,
                explanation: "Both hashing (one-way integrity check) and digital signatures (providing authenticity and integrity) ensure data integrity in different ways."
            },
            {
                question: "What does non-repudiation ensure?",
                options: [
                    "Data is encrypted",
                    "A party cannot deny performing an action",
                    "Access is properly authorized",
                    "Systems are available when needed"
                ],
                correct: 1,
                explanation: "Non-repudiation ensures that a party cannot deny the authenticity of their signature or actions, commonly achieved through digital signatures."
            },
            {
                question: "Which of the following is an example of multifactor authentication?",
                options: [
                    "Password and username",
                    "Password and security questions",
                    "Fingerprint and password",
                    "Email and phone number"
                ],
                correct: 2,
                explanation: "Multifactor authentication requires two or more factors from different categories: something you know, have, or are. Fingerprint (biometric) + password is multifactor."
            },
            {
                question: "What is the principle of least privilege?",
                options: [
                    "Users should have maximum access to all resources",
                    "Users should have the minimum access necessary to perform their job",
                    "Administrators should have unlimited access",
                    "Guest accounts should have read-only access"
                ],
                correct: 1,
                explanation: "The principle of least privilege states that users and processes should have only the minimum access rights necessary to perform their tasks."
            },
            {
                question: "Which term describes the practice of granting users more access over time?",
                options: [
                    "Privilege escalation",
                    "Access creep",
                    "Role expansion",
                    "Privilege inflation"
                ],
                correct: 1,
                explanation: "Access creep occurs when users accumulate more access privileges over time without proper review, often leading to excessive permissions."
            },
            {
                question: "What is the primary goal of defense in depth?",
                options: [
                    "To rely on a single strong security measure",
                    "To implement multiple layers of security controls",
                    "To focus only on network security",
                    "To prioritize perimeter security only"
                ],
                correct: 1,
                explanation: "Defense in depth implements multiple layers of security controls throughout a system to provide redundancy and comprehensive protection."
            },
            {
                question: "Which type of encryption uses the same key for encryption and decryption?",
                options: [
                    "Asymmetric encryption",
                    "Symmetric encryption",
                    "Hash encryption",
                    "Public key encryption"
                ],
                correct: 1,
                explanation: "Symmetric encryption uses the same key for both encryption and decryption, making it faster but requiring secure key exchange."
            },
            {
                question: "What does a digital signature provide?",
                options: [
                    "Confidentiality only",
                    "Integrity and non-repudiation",
                    "Availability only",
                    "Authorization only"
                ],
                correct: 1,
                explanation: "Digital signatures provide both integrity (ensuring data hasn't been altered) and non-repudiation (proving the sender's identity)."
            },
            {
                question: "Which security concept ensures that information is accessible only to authorized users?",
                options: [
                    "Integrity",
                    "Availability",
                    "Confidentiality",
                    "Authentication"
                ],
                correct: 2,
                explanation: "Confidentiality ensures that information is accessible only to authorized users, typically achieved through encryption and access controls."
            },
            {
                question: "What is the main difference between symmetric and asymmetric encryption?",
                options: [
                    "Symmetric is faster but requires key exchange",
                    "Asymmetric is faster but requires key exchange",
                    "Symmetric uses one key, asymmetric uses two keys",
                    "Asymmetric provides better confidentiality"
                ],
                correct: 2,
                explanation: "Symmetric encryption uses one key for both operations, while asymmetric encryption uses a pair of keys (public and private)."
            },
            {
                question: "Which access control model is most appropriate for an organization with clearly defined job roles?",
                options: [
                    "DAC",
                    "MAC",
                    "RBAC",
                    "ABAC"
                ],
                correct: 2,
                explanation: "RBAC (Role-Based Access Control) is ideal when access permissions are tied to specific job roles within an organization."
            },
            {
                question: "What is the purpose of a digital certificate?",
                options: [
                    "To encrypt data",
                    "To verify the identity of an entity",
                    "To store passwords",
                    "To create backups"
                ],
                correct: 1,
                explanation: "Digital certificates are used to verify the identity of an entity and establish trust, commonly used in PKI (Public Key Infrastructure)."
            },
            {
                question: "Which principle states that systems should fail in a secure state?",
                options: [
                    "Fail securely",
                    "Fail fast",
                    "Fail gracefully",
                    "Fail open"
                ],
                correct: 0,
                explanation: "The fail securely principle ensures that when systems fail, they do so in a secure manner rather than becoming more vulnerable."
            },
            {
                question: "What does RBAC stand for?",
                options: [
                    "Rule-Based Access Control",
                    "Role-Based Access Control",
                    "Resource-Based Access Control",
                    "Relationship-Based Access Control"
                ],
                correct: 1,
                explanation: "RBAC stands for Role-Based Access Control, where access permissions are assigned based on a user's role within an organization."
            },
            {
                question: "Which security control type is designed to detect incidents?",
                options: [
                    "Preventive",
                    "Detective",
                    "Corrective",
                    "Deterrent"
                ],
                correct: 1,
                explanation: "Detective controls are designed to identify and detect security incidents, such as IDS/IPS systems and SIEM monitoring."
            },
            {
                question: "What is the main purpose of the separation of duties principle?",
                options: [
                    "To reduce the number of people who need access",
                    "To ensure no single person has control over all aspects of a critical process",
                    "To improve system performance",
                    "To simplify access management"
                ],
                correct: 1,
                explanation: "Separation of duties ensures that no single individual has control over all aspects of a critical process, reducing the risk of fraud or errors."
            },
            {
                question: "Which of the following is an example of single sign-on (SSO)?",
                options: [
                    "Logging into multiple systems with different passwords",
                    "Logging into multiple systems with the same password",
                    "One set of credentials provides access to multiple systems",
                    "Each system requires separate authentication"
                ],
                correct: 2,
                explanation: "Single sign-on (SSO) allows users to authenticate once and gain access to multiple systems without re-authenticating."
            },
            {
                question: "What is the primary benefit of using role-based access control over individual user permissions?",
                options: [
                    "Better performance",
                    "Easier management and reduced administrative overhead",
                    "More secure than individual permissions",
                    "Requires less storage space"
                ],
                correct: 1,
                explanation: "RBAC simplifies access management by grouping permissions based on roles, making it easier to manage and reducing administrative overhead."
            },
            {
                question: "Which security concept ensures data accuracy and completeness?",
                options: [
                    "Confidentiality",
                    "Availability",
                    "Integrity",
                    "Non-repudiation"
                ],
                correct: 2,
                explanation: "Integrity ensures that data remains accurate and complete, typically achieved through hashing, checksums, and digital signatures."
            },
            {
                question: "What does AAA stand for in cybersecurity?",
                options: [
                    "Assess, Analyze, Authorize",
                    "Authentication, Authorization, Accounting",
                    "Access, Audit, Allow",
                    "Administer, Authorize, Account"
                ],
                correct: 1,
                explanation: "AAA stands for Authentication, Authorization, and Accounting - a comprehensive framework for managing user access and activities."
            },
            {
                question: "Which type of authentication involves 'something you are'?",
                options: [
                    "Knowledge-based authentication",
                    "Token-based authentication",
                    "Biometric authentication",
                    "Multi-factor authentication"
                ],
                correct: 2,
                explanation: "Biometric authentication uses physical characteristics like fingerprints, retinal scans, or voice patterns - essentially 'something you are'."
            }
        ]
    },
    d1q2: {
        title: "Domain 1 Quiz 2: Access Control & Encryption",
        questions: [
            {
                question: "Which access control model uses attributes of users, resources, and environment for access decisions?",
                options: [
                    "DAC",
                    "MAC",
                    "RBAC",
                    "ABAC"
                ],
                correct: 3,
                explanation: "ABAC (Attribute-Based Access Control) makes access decisions based on attributes of users, resources, and the environment."
            },
            {
                question: "What is the main advantage of elliptic curve cryptography (ECC) over RSA?",
                options: [
                    "Better compatibility",
                    "Smaller key sizes for equivalent security",
                    "Faster computation",
                    "More widely supported"
                ],
                correct: 1,
                explanation: "ECC provides equivalent security to RSA with much smaller key sizes, making it more efficient for constrained environments."
            },
            {
                question: "Which protocol provides secure remote login and command execution?",
                options: [
                    "Telnet",
                    "SSH",
                    "FTP",
                    "HTTP"
                ],
                correct: 1,
                explanation: "SSH (Secure Shell) provides secure remote login and command execution, replacing the insecure Telnet protocol."
            },
            {
                question: "What is the purpose of a certificate authority (CA)?",
                options: [
                    "To encrypt network traffic",
                    "To issue and manage digital certificates",
                    "To monitor network performance",
                    "To manage user passwords"
                ],
                correct: 1,
                explanation: "Certificate Authorities (CAs) are trusted third parties that issue and manage digital certificates, forming the foundation of PKI."
            },
            {
                question: "Which encryption algorithm is considered quantum-resistant?",
                options: [
                    "RSA-2048",
                    "AES-256",
                    "ECC P-256",
                    "Post-quantum algorithms"
                ],
                correct: 3,
                explanation: "Post-quantum algorithms are specifically designed to be resistant to attacks from quantum computers, unlike current RSA, AES, or ECC implementations."
            },
            {
                question: "What does PBKDF2 stand for?",
                options: [
                    "Public Key Derivation Function 2",
                    "Password-Based Key Derivation Function 2",
                    "Private Key Derivation Function 2",
                    "Protocol-Based Key Derivation Function 2"
                ],
                correct: 1,
                explanation: "PBKDF2 (Password-Based Key Derivation Function 2) is used to derive encryption keys from passwords, making brute force attacks more difficult."
            },
            {
                question: "Which principle states that security mechanisms should be as simple as possible?",
                options: [
                    "Fail securely",
                    "Economy of mechanism",
                    "Least privilege",
                    "Separation of duties"
                ],
                correct: 1,
                explanation: "Economy of mechanism advocates for simple, understandable security designs rather than complex ones that are harder to secure properly."
            },
            {
                question: "What is the main purpose of salting in password storage?",
                options: [
                    "To make passwords longer",
                    "To prevent rainbow table attacks",
                    "To encrypt the password",
                    "To store passwords in plain text"
                ],
                correct: 1,
                explanation: "Salting adds random data to passwords before hashing, preventing pre-computed rainbow table attacks on stolen password databases."
            },
            {
                question: "Which access control model is most flexible for complex environments?",
                options: [
                    "DAC",
                    "MAC",
                    "RBAC",
                    "ABAC"
                ],
                correct: 3,
                explanation: "ABAC provides the most flexibility by considering multiple attributes (user, resource, environment) for access decisions, suitable for complex scenarios."
            },
            {
                question: "What is the difference between encryption and hashing?",
                options: [
                    "Encryption is one-way, hashing is reversible",
                    "Encryption is reversible, hashing is one-way",
                    "Both are irreversible",
                    "Both are reversible"
                ],
                correct: 1,
                explanation: "Encryption is designed to be reversible (decryption), while hashing is a one-way function that cannot be reversed to obtain the original input."
            },
            {
                question: "Which protocol is used for secure email transmission?",
                options: [
                    "SMTP",
                    "HTTP",
                    "S/MIME",
                    "POP3"
                ],
                correct: 2,
                explanation: "S/MIME (Secure/Multipurpose Internet Mail Extensions) provides security services for electronic mail including encryption and digital signatures."
            },
            {
                question: "What is the purpose of a key derivation function (KDF)?",
                options: [
                    "To encrypt data directly",
                    "To generate encryption keys from passwords or other sources",
                    "To decrypt encrypted data",
                    "To store encryption keys"
                ],
                correct: 1,
                explanation: "KDFs are used to derive strong encryption keys from passwords or other input sources, making the resulting keys more resistant to attacks."
            },
            {
                question: "Which access control approach is best for temporary access requirements?",
                options: [
                    "Static role assignments",
                    "Dynamic access control",
                    "Rule-based access control",
                    "Discretionary access control"
                ],
                correct: 1,
                explanation: "Dynamic access control allows for real-time access adjustments based on current conditions, making it ideal for temporary access needs."
            },
            {
                question: "What does forward secrecy provide?",
                options: [
                    "Protection against future quantum computers",
                    "Protection of past communications if a key is compromised",
                    "Protection during data transmission only",
                    "Protection of stored data"
                ],
                correct: 1,
                explanation: "Forward secrecy ensures that if a long-term key is compromised, past communications remain secure because each session uses unique keys."
            },
            {
                question: "Which standard defines the format for X.509 digital certificates?",
                options: [
                    "ISO 27001",
                    "RFC 5280",
                    "NIST SP 800-53",
                    "FIPS 140-2"
                ],
                correct: 1,
                explanation: "RFC 5280 defines the format and semantics of X.509 digital certificates and certificate revocation lists (CRLs)."
            },
            {
                question: "What is the main advantage of bcrypt over simple hashing algorithms?",
                options: [
                    "Faster computation",
                    "Built-in salting and computational expense",
                    "Smaller hash size",
                    "Better compatibility"
                ],
                correct: 1,
                explanation: "bcrypt includes built-in salting and is designed to be computationally expensive, making it resistant to brute force and rainbow table attacks."
            },
            {
                question: "Which protocol layer does IPSec operate at?",
                options: [
                    "Application layer",
                    "Transport layer",
                    "Network layer",
                    "Data link layer"
                ],
                correct: 2,
                explanation: "IPSec operates at the network layer (Layer 3), providing security for IP communications regardless of the application layer protocols."
            },
            {
                question: "What is the purpose of a certificate revocation list (CRL)?",
                options: [
                    "To store new certificates",
                    "To list certificates that are no longer valid",
                    "To generate new encryption keys",
                    "To verify digital signatures"
                ],
                correct: 1,
                explanation: "CRLs contain lists of certificates that have been revoked before their expiration date and should no longer be trusted."
            },
            {
                question: "Which access control model combines elements of RBAC and ABAC?",
                options: [
                    "Traditional DAC",
                    "ReBAC (Relationship-Based Access Control)",
                    "Context-Aware Access Control",
                    "Rule-Based Access Control"
                ],
                correct: 2,
                explanation: "Context-Aware Access Control combines RBAC principles with ABAC's attribute-based evaluation to make dynamic access decisions."
            },
            {
                question: "What does perfect forward secrecy require?",
                options: [
                    "Using RSA encryption",
                    "Using symmetric encryption only",
                    "Using unique session keys for each connection",
                    "Using long-term encryption keys"
                ],
                correct: 2,
                explanation: "Perfect forward secrecy requires using unique, ephemeral keys for each communication session, ensuring past communications remain secure if long-term keys are compromised."
            },
            {
                question: "Which type of cipher operates on one character or bit at a time?",
                options: [
                    "Block cipher",
                    "Stream cipher",
                    "Substitution cipher",
                    "Transposition cipher"
                ],
                correct: 1,
                explanation: "Stream ciphers encrypt data one character or bit at a time, as opposed to block ciphers which operate on fixed-size blocks."
            },
            {
                question: "What is the main security benefit of using a hardware security module (HSM)?",
                options: [
                    "Faster processing",
                    "Lower cost",
                    "Protection of cryptographic keys from physical and logical attacks",
                    "Easier management"
                ],
                correct: 2,
                explanation: "HSMs provide strong protection for cryptographic keys through tamper-resistant hardware, preventing both physical and logical attacks."
            },
            {
                question: "Which access control principle helps prevent insider threats?",
                options: [
                    "Single sign-on",
                    "Separation of duties",
                    "Certificate-based authentication",
                    "Role-based access control"
                ],
                correct: 1,
                explanation: "Separation of duties prevents insider threats by ensuring that no single individual has control over all aspects of critical operations."
            },
            {
                question: "What is the primary purpose of a cryptographic nonce?",
                options: [
                    "To provide encryption",
                    "To prevent replay attacks by ensuring uniqueness",
                    "To create digital signatures",
                    "To store passwords securely"
                ],
                correct: 1,
                explanation: "A nonce (number used once) prevents replay attacks by ensuring that each cryptographic operation uses a unique value."
            },
            {
                question: "Which encryption mode provides both confidentiality and authenticity?",
                options: [
                    "ECB mode",
                    "CBC mode",
                    "GCM mode",
                    "CTR mode"
                ],
                correct: 2,
                explanation: "GCM (Galois/Counter Mode) provides both confidentiality through encryption and authenticity through authentication, making it an AEAD (Authenticated Encryption with Associated Data) mode."
            },
            {
                question: "What does NIST recommend for password hashing?",
                options: [
                    "MD5",
                    "SHA-1",
                    "Bcrypt, scrypt, or PBKDF2",
                    "Simple SHA-256"
                ],
                correct: 2,
                explanation: "NIST recommends using password hashing functions like bcrypt, scrypt, or PBKDF2 that are designed to be computationally expensive and resistant to brute force attacks."
            }
        ]
    }
};

// Additional quiz databases would be defined here for domains 2-5
// For brevity, I'll include a few more key quizzes

const quizDatabaseD2 = {
    d2q1: {
        title: "Domain 2 Quiz 1: Threats and Attack Methods",
        questions: [
            {
                question: "Which type of malware replicates itself across networks without user interaction?",
                options: [
                    "Virus",
                    "Worm",
                    "Trojan",
                    "Spyware"
                ],
                correct: 1,
                explanation: "Worms are self-replicating malware that spread across networks without requiring user interaction, unlike viruses which need host programs."
            },
            {
                question: "What is the main characteristic of Advanced Persistent Threats (APTs)?",
                options: [
                    "Quick attacks with immediate damage",
                    "Nation-state level attacks with long-term presence",
                    "Attacks only targeting financial institutions",
                    "Attacks using only social engineering"
                ],
                correct: 1,
                explanation: "APTs are sophisticated, long-term campaigns typically conducted by nation-states or organized groups, with the goal of stealing information over extended periods."
            },
            {
                question: "Which social engineering technique targets high-profile individuals?",
                options: [
                    "Phishing",
                    "Spear phishing",
                    "Whaling",
                    "Baiting"
                ],
                correct: 2,
                explanation: "Whaling is a form of phishing that specifically targets high-profile individuals like executives, politicians, or celebrities."
            },
            {
                question: "What is a zero-day vulnerability?",
                options: [
                    "A vulnerability that is 0 days old",
                    "A vulnerability unknown to the vendor with no available patch",
                    "A vulnerability with maximum severity rating",
                    "A vulnerability that affects zero systems"
                ],
                correct: 1,
                explanation: "A zero-day vulnerability is a security flaw unknown to the software vendor, meaning no patch or fix is available at the time of discovery."
            },
            {
                question: "Which malware type encrypts files and demands payment for decryption?",
                options: [
                    "Virus",
                    "Worm",
                    "Trojan",
                    "Ransomware"
                ],
                correct: 3,
                explanation: "Ransomware encrypts victim's files and demands payment (usually cryptocurrency) in exchange for the decryption key."
            },
            {
                question: "What is the primary goal of a DDoS attack?",
                options: [
                    "To steal data",
                    "To make services unavailable",
                    "To install malware",
                    "To gain unauthorized access"
                ],
                correct: 1,
                explanation: "DDoS (Distributed Denial of Service) attacks aim to overwhelm systems and make services unavailable to legitimate users."
            },
            {
                question: "Which attack vector involves following someone through secure areas?",
                options: [
                    "Phishing",
                    "Tailgating",
                    "Pretexting",
                    "Baiting"
                ],
                correct: 1,
                explanation: "Tailgating is a physical security attack where an unauthorized person follows an authorized person through secured entrances."
            },
            {
                question: "What is the main difference between viruses and worms?",
                options: [
                    "Viruses are more dangerous",
                    "Worms self-replicate, viruses need host programs",
                    "Viruses spread faster",
                    "There is no difference"
                ],
                correct: 1,
                explanation: "Worms are self-replicating and can spread across networks independently, while viruses require host programs to attach to and spread."
            },
            {
                question: "Which type of attack uses fraudulent emails to trick users?",
                options: [
                    "Spear phishing",
                    "Phishing",
                    "Whaling",
                    "All of the above"
                ],
                correct: 3,
                explanation: "All these are types of phishing attacks - phishing (general), spear phishing (targeted), and whaling (high-profile targets) all use fraudulent emails."
            },
            {
                question: "What is a botnet?",
                options: [
                    "A network of infected computers controlled by attackers",
                    "A secure network configuration",
                    "A type of antivirus software",
                    "A network monitoring tool"
                ],
                correct: 0,
                explanation: "A botnet is a network of compromised computers (bots) controlled by attackers, often used for DDoS attacks, spam distribution, or data theft."
            },
            {
                question: "Which indicator might suggest a phishing email?",
                options: [
                    "Urgent language requesting immediate action",
                    "Generic greetings like 'Dear Customer'",
                    "Suspicious links or attachments",
                    "All of the above"
                ],
                correct: 3,
                explanation: "Phishing emails often exhibit urgent language, generic greetings, suspicious links/attachments, and request sensitive information."
            },
            {
                question: "What is the primary motivation of script kiddies?",
                options: [
                    "Financial gain",
                    "Espionage",
                    "Recognition or excitement",
                    "Hacktivism"
                ],
                correct: 2,
                explanation: "Script kiddies typically lack advanced skills and attack for recognition, excitement, or to prove their abilities, often using pre-written tools."
            },
            {
                question: "Which term describes software that secretly monitors user activities?",
                options: [
                    "Adware",
                    "Spyware",
                    "Ransomware",
                    "Virus"
                ],
                correct: 1,
                explanation: "Spyware is designed to secretly monitor user activities, collect information, and report back to the attacker without user knowledge."
            },
            {
                question: "What is a man-in-the-middle (MITM) attack?",
                options: [
                    "Attacker intercepts communications between two parties",
                    "Attacker directly attacks a central server",
                    "Attacker poses as a trusted entity",
                    "Attacker overloads a server with requests"
                ],
                correct: 0,
                explanation: "In a MITM attack, the attacker intercepts and potentially alters communications between two parties who believe they are communicating directly."
            },
            {
                question: "Which type of malware displays unwanted advertisements?",
                options: [
                    "Spyware",
                    "Adware",
                    "Ransomware",
                    "Worm"
                ],
                correct: 1,
                explanation: "Adware automatically displays unwanted advertisements, often through pop-ups or browser redirects, and may track browsing behavior."
            },
            {
                question: "What is the main goal of SQL injection attacks?",
                options: [
                    "To crash web servers",
                    "To manipulate database queries to gain unauthorized access",
                    "To spread malware",
                    "To steal user credentials"
                ],
                correct: 1,
                explanation: "SQL injection attacks manipulate database queries by injecting malicious SQL code, allowing attackers to view, modify, or delete database data."
            },
            {
                question: "Which attack method involves creating fake websites to trick users?",
                options: [
                    "Typosquatting",
                    "Clickjacking",
                    "Watering hole attack",
                    "All of the above"
                ],
                correct: 0,
                explanation: "Typosquatting involves registering domain names that are misspellings of popular websites to trick users into visiting fake sites."
            },
            {
                question: "What is a watering hole attack?",
                options: [
                    "Attacking water treatment facilities",
                    "Compromising websites frequently visited by target victims",
                    "Attacking through water cooling systems",
                    "Using water as an attack vector"
                ],
                correct: 1,
                explanation: "Watering hole attacks compromise websites that target groups frequently visit, then exploit vulnerabilities when victims browse those sites."
            },
            {
                question: "Which factor makes spear phishing more dangerous than regular phishing?",
                options: [
                    "It uses more emails",
                    "It's targeted with personal information",
                    "It's faster",
                    "It's more automated"
                ],
                correct: 1,
                explanation: "Spear phishing uses personalized information about victims to appear more legitimate, making it more convincing and harder to detect."
            },
            {
                question: "What is the primary characteristic of ransomware attacks?",
                options: [
                    "Stealing data quietly",
                    "Displaying advertisements",
                    "Demanding payment for file decryption",
                    "Monitoring user behavior"
                ],
                correct: 2,
                explanation: "Ransomware encrypts victim's files and demands payment for decryption keys, making it a financially motivated attack."
            },
            {
                question: "Which term describes attackers who threaten to release sensitive information?",
                options: [
                    "Blackmail",
                    "Extortion",
                    "Coercion",
                    "Intimidation"
                ],
                correct: 1,
                explanation: "Extortion involves threatening to release sensitive information or cause harm unless demands (usually payment) are met."
            },
            {
                question: "What is a keylogger?",
                options: [
                    "A tool to monitor keyboard performance",
                    "Software that records keystrokes to steal information",
                    "A security patch for keyboards",
                    "A backup tool for user data"
                ],
                correct: 1,
                explanation: "Keyloggers are malicious programs that record keystrokes, often to steal passwords, credit card numbers, and other sensitive information."
            },
            {
                question: "Which social engineering technique involves offering something enticing?",
                options: [
                    "Pretexting",
                    "Baiting",
                    "Quid pro quo",
                    "Tailgating"
                ],
                correct: 1,
                explanation: "Baiting involves offering something enticing (like free software or USB drives) to lure victims into executing malicious actions."
            },
            {
                question: "What is the main goal of credential stuffing attacks?",
                options: [
                    "Creating fake accounts",
                    "Using stolen credentials to gain unauthorized access",
                    "Stealing passwords from databases",
                    "Testing password strength"
                ],
                correct: 1,
                explanation: "Credential stuffing uses stolen username/password combinations from one breach to attempt login on other services, hoping users reused credentials."
            },
            {
                question: "Which attack vector involves exploiting software vulnerabilities?",
                options: [
                    "Social engineering",
                    "Technical attacks",
                    "Physical attacks",
                    "Environmental attacks"
                ],
                correct: 1,
                explanation: "Technical attacks exploit software vulnerabilities, configuration weaknesses, or other technical flaws to compromise systems."
            },
            {
                question: "What is the primary defense against social engineering attacks?",
                options: [
                    "Technical controls",
                    "User education and awareness",
                    "Physical security",
                    "Network segmentation"
                ],
                correct: 1,
                explanation: "Security awareness training is the best defense against social engineering, as it helps users recognize and resist manipulation attempts."
            }
        ]
    }
};

// Add more quiz databases for other domains...
// For brevity, I'll include just one more for domain 5

const quizDatabaseD5 = {
    d5q1: {
        title: "Domain 5 Quiz 1: Governance and Risk Management",
        questions: [
            {
                question: "What is the primary purpose of security governance?",
                options: [
                    "To implement technical security controls",
                    "To establish policies, procedures, and oversight for security programs",
                    "To monitor network traffic",
                    "To train employees on security"
                ],
                correct: 1,
                explanation: "Security governance establishes the framework of policies, procedures, and oversight needed to manage and direct security programs effectively."
            },
            {
                question: "Which framework is most comprehensive for enterprise security governance?",
                options: [
                    "ISO 27001",
                    "NIST Cybersecurity Framework",
                    "COSO",
                    "All of the above"
                ],
                correct: 3,
                explanation: "All these frameworks provide governance structures, though ISO 27001 focuses on information security, COSO on enterprise governance, and NIST CSF on cybersecurity practices."
            },
            {
                question: "What is the main purpose of a risk assessment?",
                options: [
                    "To eliminate all risks",
                    "To identify, analyze, and prioritize risks to organizational assets",
                    "To assign blame for security incidents",
                    "To create security policies"
                ],
                correct: 1,
                explanation: "Risk assessments systematically identify, analyze, and prioritize risks to help organizations make informed decisions about risk treatment."
            },
            {
                question: "Which risk response strategy involves transferring risk to a third party?",
                options: [
                    "Risk mitigation",
                    "Risk acceptance",
                    "Risk transference",
                    "Risk avoidance"
                ],
                correct: 2,
                explanation: "Risk transference shifts the financial burden of risk to third parties, commonly through insurance or outsourcing agreements."
            },
            {
                question: "What is the formula for calculating risk in most frameworks?",
                options: [
                    "Risk = Threat × Vulnerability",
                    "Risk = Asset Value × Threat × Vulnerability",
                    "Risk = Asset Value × Threat × Vulnerability × Impact",
                    "Risk = Threat - Control Effectiveness"
                ],
                correct: 2,
                explanation: "Most risk frameworks calculate risk as: Risk = Asset Value × Threat × Vulnerability × Impact, though some variations exist."
            },
            {
                question: "Which principle ensures proper segregation of duties in security governance?",
                options: [
                    "Least privilege",
                    "Separation of duties",
                    "Need to know",
                    "Defense in depth"
                ],
                correct: 1,
                explanation: "Separation of duties ensures that no single individual has control over all aspects of critical processes, reducing fraud and error risk."
            },
            {
                question: "What is the primary focus of FAIR (Factor Analysis of Information Risk)?",
                options: [
                    "Technical vulnerability assessment",
                    "Quantitative risk analysis with financial impact",
                    "Qualitative risk assessment",
                    "Compliance monitoring"
                ],
                correct: 1,
                explanation: "FAIR provides a methodology for quantitative risk analysis that focuses on understanding and measuring financial impacts of cyber risks."
            },
            {
                question: "Which governance activity ensures security measures align with business objectives?",
                options: [
                    "Technical implementation",
                    "Strategic alignment",
                    "Compliance monitoring",
                    "Incident response"
                ],
                correct: 1,
                explanation: "Strategic alignment ensures that security investments and initiatives support and enable the organization's business objectives."
            },
            {
                question: "What is the main purpose of security metrics in governance?",
                options: [
                    "To impress senior management",
                    "To measure program effectiveness and guide decision-making",
                    "To justify security budgets",
                    "To meet regulatory requirements"
                ],
                correct: 1,
                explanation: "Security metrics provide measurable indicators of program performance, enabling data-driven decision-making and continuous improvement."
            },
            {
                question: "Which document typically contains high-level security directives from executive leadership?",
                options: [
                    "Procedures",
                    "Guidelines",
                    "Policies",
                    "Standards"
                ],
                correct: 2,
                explanation: "Security policies are high-level directives from executive leadership that establish the overall security direction and requirements."
            },
            {
                question: "What is the primary goal of risk appetite statements?",
                options: [
                    "To eliminate all organizational risks",
                    "To define the level of risk the organization is willing to accept",
                    "To transfer all risks to insurance companies",
                    "To implement maximum security controls"
                ],
                correct: 1,
                explanation: "Risk appetite statements define the amount and type of risk an organization is willing to accept in pursuit of its objectives."
            },
            {
                question: "Which role is typically responsible for setting organizational risk appetite?",
                options: [
                    "CISO",
                    "IT Manager",
                    "Board of Directors",
                    "Security Team"
                ],
                correct: 2,
                explanation: "The Board of Directors or highest executive leadership typically sets organizational risk appetite as part of strategic governance."
            },
            {
                question: "What is the main purpose of the three lines of defense model?",
                options: [
                    "To reduce security costs",
                    "To clarify roles and responsibilities for risk management",
                    "To improve technical security",
                    "To ensure compliance"
                ],
                correct: 1,
                explanation: "The three lines of defense model clarifies roles and responsibilities across operational management, risk management/compliance, and internal audit."
            },
            {
                question: "Which governance body typically includes executive leadership and approves security policies?",
                options: [
                    "Security operations team",
                    "Security steering committee",
                    "IT department",
                    "End users"
                ],
                correct: 1,
                explanation: "Security steering committees typically include executive leadership and are responsible for approving policies and major security initiatives."
            },
            {
                question: "What is the primary focus of the second line of defense in risk governance?",
                options: [
                    "Implementing security controls",
                    "Monitoring risk management activities and compliance",
                    "Conducting security audits",
                    "Reporting to regulators"
                ],
                correct: 1,
                explanation: "The second line of defense (risk management/compliance function) monitors and oversees risk management activities and ensures compliance."
            },
            {
                question: "Which assessment method provides the most comprehensive view of organizational risk?",
                options: [
                    "Vulnerability assessment",
                    "Penetration testing",
                    "Enterprise risk assessment",
                    "Compliance audit"
                ],
                correct: 2,
                explanation: "Enterprise risk assessments provide comprehensive views by considering strategic, operational, financial, and compliance risks across the entire organization."
            },
            {
                question: "What is the main purpose of residual risk analysis?",
                options: [
                    "To identify initial risks",
                    "To understand risks remaining after controls are implemented",
                    "To transfer all risks to insurance",
                    "To eliminate all risks"
                ],
                correct: 1,
                explanation: "Residual risk analysis examines the risks that remain after security controls and risk treatment measures have been implemented."
            },
            {
                question: "Which document provides detailed instructions for implementing security controls?",
                options: [
                    "Policies",
                    "Standards",
                    "Procedures",
                    "Guidelines"
                ],
                correct: 2,
                explanation: "Procedures provide detailed, step-by-step instructions for implementing security controls and completing specific tasks."
            },
            {
                question: "What is the primary goal of risk treatment planning?",
                options: [
                    "To identify all possible risks",
                    "To define how identified risks will be managed",
                    "To assign blame for risks",
                    "To eliminate risk assessment"
                ],
                correct: 1,
                explanation: "Risk treatment planning defines how identified risks will be managed through mitigation, acceptance, transference, or avoidance strategies."
            },
            {
                question: "Which principle ensures that security controls support business objectives?",
                options: [
                    "Technical effectiveness",
                    "Business alignment",
                    "Regulatory compliance",
                    "Cost minimization"
                ],
                correct: 1,
                explanation: "Business alignment ensures that security controls and initiatives directly support and enable the organization's strategic objectives."
            },
            {
                question: "What is the main purpose of governance metrics and KPIs?",
                options: [
                    "To meet regulatory requirements only",
                    "To measure program effectiveness and drive continuous improvement",
                    "To justify security budgets",
                    "To compare with other organizations"
                ],
                correct: 1,
                explanation: "Governance metrics and KPIs measure program effectiveness, enable data-driven decisions, and drive continuous improvement of security programs."
            },
            {
                question: "Which governance activity involves periodic review of security program effectiveness?",
                options: [
                    "Implementation",
                    "Monitoring and reporting",
                    "Strategic planning",
                    "Budget allocation"
                ],
                correct: 1,
                explanation: "Monitoring and reporting involves ongoing assessment of security program effectiveness and regular communication to stakeholders."
            },
            {
                question: "What is the primary focus of strategic risk management?",
                options: [
                    "Technical security controls",
                    "Risks that could impact organizational strategy and objectives",
                    "Operational security procedures",
                    "Compliance requirements"
                ],
                correct: 1,
                explanation: "Strategic risk management focuses on risks that could significantly impact the organization's ability to achieve its strategic objectives."
            },
            {
                question: "Which document type typically contains mandatory requirements?",
                options: [
                    "Guidelines",
                    "Policies",
                    "Procedures",
                    "Best practices"
                ],
                correct: 1,
                explanation: "Policies typically contain mandatory requirements that must be followed, while guidelines and best practices are more flexible recommendations."
            },
            {
                question: "What is the main purpose of risk tolerance statements?",
                options: [
                    "To eliminate organizational risks",
                    "To define acceptable variation in risk levels for specific objectives",
                    "To transfer all risks to third parties",
                    "To implement maximum security controls"
                ],
                correct: 1,
                explanation: "Risk tolerance statements define the acceptable range of variation in risk levels for specific objectives within the broader risk appetite."
            },
            {
                question: "Which governance function ensures security program accountability?",
                options: [
                    "Strategic oversight",
                    "Performance monitoring",
                    "Compliance enforcement",
                    "All of the above"
                ],
                correct: 3,
                explanation: "Accountability is ensured through strategic oversight, performance monitoring, and compliance enforcement working together effectively."
            }
        ]
    }
};

// Combine all quiz databases
const allQuizzes = { ...quizDatabase, ...quizDatabaseD2, ...quizDatabaseD5 };

// Application state
let currentView = 'overview';
let currentQuiz = null;
let quizState = {
    currentQuestionIndex: 0,
    answers: [],
    score: 0,
    startTime: null
};

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Load progress from localStorage
    loadProgress();
    
    // Setup event listeners
    setupEventListeners();
    
    // Hide loading screen
    setTimeout(() => {
        document.getElementById('loading-screen').style.display = 'none';
    }, 3000);
}

function setupEventListeners() {
    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            const view = item.dataset.view;
            navigateToView(view);
        });
    });

    // Domain cards
    document.querySelectorAll('.domain-card').forEach(card => {
        card.addEventListener('click', () => {
            const domain = card.dataset.domain;
            navigateToView(domain);
        });
    });

    // Quiz buttons
    document.querySelectorAll('.start-quiz').forEach(button => {
        button.addEventListener('click', () => {
            const quizId = button.dataset.quiz;
            startQuiz(quizId);
        });
    });

    // Quiz modal controls
    document.getElementById('quiz-close').addEventListener('click', closeQuiz);
    document.getElementById('quiz-next').addEventListener('click', nextQuestion);
    document.getElementById('quiz-prev').addEventListener('click', previousQuestion);
    document.getElementById('retry-quiz').addEventListener('click', retryQuiz);
    document.getElementById('back-to-study').addEventListener('click', closeQuiz);
    document.getElementById('results-close').addEventListener('click', closeQuiz);

    // Mobile menu toggle
    document.getElementById('mobile-menu-toggle').addEventListener('click', toggleMobileMenu);

    // Reset progress
    document.getElementById('reset-progress').addEventListener('click', resetProgress);

    // Close quiz modal when clicking outside
    document.getElementById('quiz-modal').addEventListener('click', (e) => {
        if (e.target.id === 'quiz-modal') closeQuiz();
    });

    document.getElementById('results-modal').addEventListener('click', (e) => {
        if (e.target.id === 'results-modal') closeQuiz();
    });
}

function navigateToView(viewName) {
    // Update navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    document.querySelector(`[data-view="${viewName}"]`)?.classList.add('active');

    // Update content
    document.querySelectorAll('.view').forEach(view => {
        view.classList.remove('active');
    });
    document.getElementById(viewName).classList.add('active');

    // Update page title
    const titles = {
        'overview': 'CompTIA Security+ SY0-701 Study Platform',
        'domain1': 'Domain 1: General Security Concepts',
        'domain2': 'Domain 2: Threats, Vulnerabilities & Mitigations',
        'domain3': 'Domain 3: Security Architecture',
        'domain4': 'Domain 4: Security Operations',
        'domain5': 'Domain 5: Security Program Management'
    };
    document.getElementById('page-title').textContent = titles[viewName] || 'Security+ Study Platform';

    currentView = viewName;

    // Close mobile menu if open
    document.getElementById('sidebar').classList.remove('open');
}

function startQuiz(quizId) {
    currentQuiz = allQuizzes[quizId];
    if (!currentQuiz) {
        console.error('Quiz not found:', quizId);
        return;
    }

    // Initialize quiz state
    quizState = {
        currentQuestionIndex: 0,
        answers: [],
        score: 0,
        startTime: Date.now()
    };

    // Show quiz modal
    document.getElementById('quiz-modal').classList.add('active');
    document.getElementById('quiz-title').textContent = currentQuiz.title;
    document.getElementById('results-modal').classList.remove('active');

    // Load first question
    loadQuestion();
    updateProgress();
}

function loadQuestion() {
    const question = currentQuiz.questions[quizState.currentQuestionIndex];
    const questionContainer = document.getElementById('quiz-question');
    const optionsContainer = document.getElementById('quiz-options');
    const explanationContainer = document.getElementById('quiz-explanation');

    // Clear previous content
    questionContainer.innerHTML = question.question;
    optionsContainer.innerHTML = '';
    explanationContainer.style.display = 'none';

    // Create options
    const letters = ['A', 'B', 'C', 'D'];
    question.options.forEach((option, index) => {
        const optionDiv = document.createElement('div');
        optionDiv.className = 'option';
        optionDiv.innerHTML = `
            <span class="option-letter">${letters[index]}.</span>
            <span class="option-text">${option}</span>
        `;
        optionDiv.addEventListener('click', () => selectAnswer(index));
        optionsContainer.appendChild(optionDiv);
    });

    // Update navigation buttons
    document.getElementById('quiz-prev').disabled = quizState.currentQuestionIndex === 0;
    document.getElementById('quiz-next').textContent = 
        quizState.currentQuestionIndex === currentQuiz.questions.length - 1 ? 'Finish Quiz' : 'Next';

    // Update score
    document.getElementById('quiz-score').textContent = 
        `Score: ${quizState.score}/${quizState.currentQuestionIndex}`;
}

function selectAnswer(selectedIndex) {
    const options = document.querySelectorAll('.option');
    const currentAnswer = quizState.answers[quizState.currentQuestionIndex];

    // Remove previous selection
    options.forEach(option => option.classList.remove('selected'));

    // Add new selection
    options[selectedIndex].classList.add('selected');

    // Store answer
    quizState.answers[quizState.currentQuestionIndex] = {
        selected: selectedIndex,
        correct: currentQuiz.questions[quizState.currentQuestionIndex].correct
    };

    // Update score if this is the first time answering
    if (currentAnswer === undefined) {
        if (selectedIndex === currentQuiz.questions[quizState.currentQuestionIndex].correct) {
            quizState.score++;
            options[selectedIndex].classList.add('correct');
        } else {
            options[selectedIndex].classList.add('incorrect');
            options[currentQuiz.questions[quizState.currentQuestionIndex].correct].classList.add('correct');
        }
        updateScore();
    }

    // Show explanation
    showExplanation();
}

function showExplanation() {
    const explanation = currentQuiz.questions[quizState.currentQuestionIndex].explanation;
    const explanationContainer = document.getElementById('quiz-explanation');
    explanationContainer.innerHTML = `
        <h4>Explanation:</h4>
        <p>${explanation}</p>
    `;
    explanationContainer.style.display = 'block';
}

function nextQuestion() {
    if (quizState.currentQuestionIndex < currentQuiz.questions.length - 1) {
        quizState.currentQuestionIndex++;
        loadQuestion();
        updateProgress();
    } else {
        finishQuiz();
    }
}

function previousQuestion() {
    if (quizState.currentQuestionIndex > 0) {
        quizState.currentQuestionIndex--;
        loadQuestion();
        updateProgress();
    }
}

function updateProgress() {
    const progress = ((quizState.currentQuestionIndex + 1) / currentQuiz.questions.length) * 100;
    document.getElementById('quiz-progress').style.width = `${progress}%`;
    document.getElementById('quiz-progress-text').textContent = 
        `Question ${quizState.currentQuestionIndex + 1} of ${currentQuiz.questions.length}`;
}

function updateScore() {
    document.getElementById('quiz-score').textContent = 
        `Score: ${quizState.score}/${quizState.currentQuestionIndex + 1}`;
}

function finishQuiz() {
    const percentage = Math.round((quizState.score / currentQuiz.questions.length) * 100);
    const timeSpent = Math.round((Date.now() - quizState.startTime) / 1000 / 60); // minutes

    // Save progress
    saveQuizProgress(currentQuiz.title, percentage, quizState.score, currentQuiz.questions.length);

    // Show results
    showResults(percentage, quizState.score, currentQuiz.questions.length, timeSpent);
}

function showResults(percentage, score, total, timeSpent) {
    document.getElementById('quiz-modal').classList.remove('active');
    document.getElementById('results-modal').classList.add('active');

    // Update score display
    document.getElementById('final-percentage').textContent = `${percentage}%`;
    document.getElementById('final-score').textContent = `${score} out of ${total} correct`;

    // Update result message
    let message = '';
    if (percentage >= 90) {
        message = 'Excellent! You have a strong understanding of this domain.';
    } else if (percentage >= 80) {
        message = 'Good work! Review the missed questions to improve further.';
    } else if (percentage >= 70) {
        message = 'Fair performance. More study is recommended for this domain.';
    } else {
        message = 'Keep studying! Focus on understanding the core concepts.';
    }
    document.getElementById('result-message').textContent = message;

    // Update score circle
    const scoreCircle = document.querySelector('.score-circle');
    const degrees = (percentage / 100) * 360;
    scoreCircle.style.background = `conic-gradient(var(--primary-500) ${degrees}deg, var(--border-subtle) ${degrees}deg)`;

    // Add topic breakdown (simplified)
    const topicBreakdown = document.getElementById('topic-breakdown');
    topicBreakdown.innerHTML = `
        <div class="topic-item">
            <span class="topic-name">Overall Performance</span>
            <span class="topic-score ${getScoreClass(percentage)}">${percentage}%</span>
        </div>
        <div class="topic-item">
            <span class="topic-name">Time Spent</span>
            <span class="topic-score">${timeSpent} minutes</span>
        </div>
    `;
}

function getScoreClass(percentage) {
    if (percentage >= 85) return 'excellent';
    if (percentage >= 70) return 'good';
    return 'needs-improvement';
}

function retryQuiz() {
    startQuiz(Object.keys(allQuizzes).find(key => allQuizzes[key].title === currentQuiz.title));
}

function closeQuiz() {
    document.getElementById('quiz-modal').classList.remove('active');
    document.getElementById('results-modal').classList.remove('active');
}

function toggleMobileMenu() {
    document.getElementById('sidebar').classList.toggle('open');
}

// Progress tracking
function loadProgress() {
    const progress = localStorage.getItem('securityPlusProgress');
    if (progress) {
        const progressData = JSON.parse(progress);
        updateOverallProgress(progressData);
    }
}

function saveQuizProgress(quizTitle, percentage, score, total) {
    const progress = localStorage.getItem('securityPlusProgress') || '{}';
    const progressData = JSON.parse(progress);
    
    progressData[quizTitle] = {
        percentage,
        score,
        total,
        completed: new Date().toISOString()
    };
    
    localStorage.setItem('securityPlusProgress', JSON.stringify(progressData));
    updateOverallProgress(progressData);
}

function updateOverallProgress(progressData) {
    const quizzes = Object.keys(progressData);
    if (quizzes.length === 0) return;

    const completedQuizzes = quizzes.filter(quiz => progressData[quiz].completed);
    const progress = (completedQuizzes.length / Object.keys(allQuizzes).length) * 100;
    
    document.getElementById('overall-progress').style.width = `${progress}%`;
    document.getElementById('progress-text').textContent = `${Math.round(progress)}% Complete`;
}

function resetProgress() {
    if (confirm('Are you sure you want to reset all progress? This action cannot be undone.')) {
        localStorage.removeItem('securityPlusProgress');
        document.getElementById('overall-progress').style.width = '0%';
        document.getElementById('progress-text').textContent = '0% Complete';
    }
}

// Handle keyboard navigation
document.addEventListener('keydown', function(e) {
    if (document.getElementById('quiz-modal').classList.contains('active')) {
        switch(e.key) {
            case 'ArrowUp':
            case 'ArrowLeft':
                e.preventDefault();
                previousQuestion();
                break;
            case 'ArrowDown':
            case 'ArrowRight':
            case ' ':
                e.preventDefault();
                nextQuestion();
                break;
            case 'Escape':
                e.preventDefault();
                closeQuiz();
                break;
        }
    }
});

// Add smooth scrolling for better UX
function smoothScrollTo(element) {
    element.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Add intersection observer for animations
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
        }
    });
}, observerOptions);

// Observe elements for animation
document.addEventListener('DOMContentLoaded', () => {
    const animatedElements = document.querySelectorAll('.concept-card, .domain-card, .quiz-card');
    animatedElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(el);
    });
});

// Performance optimization: Lazy load quiz content
function preloadQuizContent() {
    Object.keys(allQuizzes).forEach(quizId => {
        const quiz = allQuizzes[quizId];
        // Preload questions without creating DOM elements
        quiz.questions.forEach(question => {
            // Could add additional preprocessing here
        });
    });
}

// Initialize preloading after page load
window.addEventListener('load', preloadQuizContent);// Additional quiz databases for complete coverage

const quizDatabaseD3 = {
    d3q1: {
        title: "Domain 3 Quiz 1: Network Architecture",
        questions: [
            {
                question: "What is the primary purpose of network segmentation?",
                options: [
                    "To improve network speed",
                    "To contain breaches and limit attack spread",
                    "To reduce network costs",
                    "To simplify network management"
                ],
                correct: 1,
                explanation: "Network segmentation primarily aims to contain security breaches and limit the spread of attacks by dividing networks into smaller, isolated segments."
            },
            {
                question: "Which network device operates at Layer 2 of the OSI model?",
                options: [
                    "Router",
                    "Switch",
                    "Hub",
                    "Gateway"
                ],
                correct: 1,
                explanation: "Switches operate at Layer 2 (Data Link layer) of the OSI model, using MAC addresses to forward frames within the same network segment."
            },
            {
                question: "What is a DMZ (Demilitarized Zone)?",
                options: [
                    "A secure internal network",
                    "A buffer zone between trusted and untrusted networks",
                    "A wireless network segment",
                    "A backup network"
                ],
                correct: 1,
                explanation: "A DMZ is a buffer zone between trusted internal networks and untrusted external networks, containing publicly accessible servers."
            },
            {
                question: "Which technology provides secure remote access to private networks over the internet?",
                options: [
                    "Firewall",
                    "VPN",
                    "Proxy server",
                    "Load balancer"
                ],
                correct: 1,
                explanation: "VPN (Virtual Private Network) creates secure tunnels over public networks to provide remote access to private network resources."
            },
            {
                question: "What is microsegmentation?",
                options: [
                    "Using smaller network cables",
                    "Creating granular security zones within networks",
                    "Reducing network size",
                    "Segmenting user accounts"
                ],
                correct: 1,
                explanation: "Microsegmentation creates granular security zones with individual security controls for specific workloads or applications, even within the same network."
            },
            {
                question: "Which protocol is used for secure web communications?",
                options: [
                    "HTTP",
                    "FTP",
                    "TLS/SSL",
                    "SMTP"
                ],
                correct: 2,
                explanation: "TLS/SSL (Transport Layer Security/Secure Sockets Layer) provides encryption for web communications, securing HTTP traffic."
            },
            {
                question: "What is the main purpose of network access control (NAC)?",
                options: [
                    "To control physical network cables",
                    "To authenticate and authorize devices before network access",
                    "To prioritize network traffic",
                    "To monitor network usage"
                ],
                correct: 1,
                explanation: "NAC systems authenticate and authorize devices before granting network access, ensuring only compliant and authorized devices can connect."
            },
            {
                question: "Which device acts as a security barrier between networks?",
                options: [
                    "Hub",
                    "Switch",
                    "Firewall",
                    "Bridge"
                ],
                correct: 2,
                explanation: "Firewalls act as security barriers between networks, filtering traffic based on security rules and policies."
            },
            {
                question: "What is a honeypot in network security?",
                options: [
                    "A trap to detect and study attackers",
                    "A type of firewall",
                    "A backup system",
                    "A network monitoring tool"
                ],
                correct: 0,
                explanation: "Honeypots are decoy systems designed to attract attackers, allowing security teams to study attack methods and techniques."
            },
            {
                question: "Which wireless security protocol is considered most secure?",
                options: [
                    "WEP",
                    "WPA",
                    "WPA2",
                    "WPA3"
                ],
                correct: 3,
                explanation: "WPA3 is the latest and most secure wireless security protocol, providing enhanced protection over previous versions."
            },
            {
                question: "What is the purpose of VLANs (Virtual LANs)?",
                options: [
                    "To increase network speed",
                    "To logically segment networks without physical separation",
                    "To provide wireless connectivity",
                    "To encrypt network traffic"
                ],
                correct: 1,
                explanation: "VLANs logically segment networks into separate broadcast domains without requiring physical separation, improving security and management."
            },
            {
                question: "Which protocol provides secure file transfer?",
                options: [
                    "FTP",
                    "HTTP",
                    "SFTP",
                    "SMTP"
                ],
                correct: 2,
                explanation: "SFTP (SSH File Transfer Protocol) provides secure file transfer by using SSH for encryption and authentication."
            },
            {
                question: "What is an air gap in security?",
                options: [
                    "A wireless connection",
                    "A network that is completely isolated from other networks",
                    "A backup connection",
                    "A secure tunnel"
                ],
                correct: 1,
                explanation: "An air gap refers to a network that is completely isolated and not connected to other networks, providing maximum security for critical systems."
            },
            {
                question: "Which technology monitors network traffic for suspicious activities?",
                options: [
                    "Firewall",
                    "IDS/IPS",
                    "Switch",
                    "Router"
                ],
                correct: 1,
                explanation: "IDS/IPS (Intrusion Detection/Prevention Systems) monitor network traffic for suspicious activities and can take action to prevent attacks."
            },
            {
                question: "What is the primary benefit of using a next-generation firewall (NGFW)?",
                options: [
                    "Faster processing",
                    "Lower cost",
                    "Application-level filtering and deep packet inspection",
                    "Better wireless support"
                ],
                correct: 2,
                explanation: "Next-generation firewalls provide application-level filtering, deep packet inspection, and advanced threat protection beyond traditional firewall capabilities."
            },
            {
                question: "Which network topology provides the most redundancy?",
                options: [
                    "Star",
                    "Ring",
                    "Mesh",
                    "Bus"
                ],
                correct: 2,
                explanation: "Mesh topology provides the most redundancy by connecting each node to multiple other nodes, ensuring alternative paths if one connection fails."
            },
            {
                question: "What is VLAN hopping?",
                options: [
                    "A method to increase VLAN performance",
                    "An attack technique to access other VLANs",
                    "A type of network monitoring",
                    "A VLAN configuration tool"
                ],
                correct: 1,
                explanation: "VLAN hopping is an attack technique where an attacker attempts to access traffic from other VLANs by exploiting switch configuration weaknesses."
            },
            {
                question: "Which port does SSH use by default?",
                options: [
                    "21",
                    "22",
                    "23",
                    "25"
                ],
                correct: 1,
                explanation: "SSH (Secure Shell) uses port 22 by default for secure remote login and command execution."
            },
            {
                question: "What is the purpose of network address translation (NAT)?",
                options: [
                    "To encrypt network traffic",
                    "To translate private IP addresses to public addresses",
                    "To compress network data",
                    "To secure network protocols"
                ],
                correct: 1,
                explanation: "NAT translates private IP addresses to public addresses, allowing multiple devices to share a single public IP address."
            },
            {
                question: "Which protocol is used for secure email transmission?",
                options: [
                    "SMTP",
                    "POP3",
                    "IMAP",
                    "All of the above can be secured"
                ],
                correct: 3,
                explanation: "All email protocols (SMTP, POP3, IMAP) can be secured using TLS/SSL to provide encryption for email transmission."
            },
            {
                question: "What is the main purpose of network monitoring?",
                options: [
                    "To increase network speed",
                    "To detect performance issues and security threats",
                    "To reduce network costs",
                    "To simplify network configuration"
                ],
                correct: 1,
                explanation: "Network monitoring helps detect performance issues, security threats, and unusual network behavior for proper network management."
            },
            {
                question: "Which technology provides both confidentiality and integrity for network communications?",
                options: [
                    "Encryption only",
                    "Hashing only",
                    "Digital signatures",
                    "Authentication protocols"
                ],
                correct: 2,
                explanation: "Digital signatures provide both confidentiality (through encryption) and integrity (through hashing) for secure communications."
            },
            {
                question: "What is the purpose of a proxy server?",
                options: [
                    "To directly connect networks",
                    "To act as an intermediary between clients and servers",
                    "To encrypt all network traffic",
                    "To monitor network performance"
                ],
                correct: 1,
                explanation: "Proxy servers act as intermediaries between client requests and target servers, providing caching, filtering, and anonymity."
            },
            {
                question: "Which network device operates at Layer 3 of the OSI model?",
                options: [
                    "Hub",
                    "Switch",
                    "Router",
                    "Bridge"
                ],
                correct: 2,
                explanation: "Routers operate at Layer 3 (Network layer) of the OSI model, using IP addresses to route packets between different networks."
            },
            {
                question: "What is the primary advantage of using software-defined networking (SDN)?",
                options: [
                    "Lower hardware costs",
                    "Centralized network control and programmability",
                    "Better physical security",
                    "Reduced network complexity"
                ],
                correct: 1,
                explanation: "SDN provides centralized network control and programmability, allowing dynamic configuration and management of network resources."
            },
            {
                question: "Which security measure protects against man-in-the-middle attacks?",
                options: [
                    "Antivirus software",
                    "Digital certificates and PKI",
                    "Network firewalls",
                    "Password protection"
                ],
                correct: 1,
                explanation: "Digital certificates and PKI (Public Key Infrastructure) help protect against man-in-the-middle attacks by verifying the identity of communicating parties."
            }
        ]
    },
    d3q2: {
        title: "Domain 3 Quiz 2: Cloud & ICS Security",
        questions: [
            {
                question: "In which cloud service model does the customer manage the operating system and applications?",
                options: [
                    "SaaS",
                    "PaaS",
                    "IaaS",
                    "FaaS"
                ],
                correct: 2,
                explanation: "In IaaS (Infrastructure as a Service), customers manage the operating system, applications, and data, while the cloud provider manages the underlying infrastructure."
            },
            {
                question: "What is the shared responsibility model in cloud computing?",
                options: [
                    "Both cloud provider and customer share equally in all responsibilities",
                    "Security responsibilities are divided between cloud provider and customer based on service model",
                    "The customer is always responsible for all security",
                    "The cloud provider is always responsible for all security"
                ],
                correct: 1,
                explanation: "The shared responsibility model divides security responsibilities between the cloud provider and customer, varying by the specific cloud service model (IaaS, PaaS, SaaS)."
            },
            {
                question: "Which cloud deployment model provides the highest level of control?",
                options: [
                    "Public cloud",
                    "Private cloud",
                    "Hybrid cloud",
                    "Multi-cloud"
                ],
                correct: 1,
                explanation: "Private cloud provides the highest level of control as it's dedicated to a single organization and can be fully customized to specific requirements."
            },
            {
                question: "What is a key characteristic of SCADA systems?",
                options: [
                    "They are typically used in office environments",
                    "They control industrial processes and infrastructure",
                    "They are primarily for data storage",
                    "They are designed for internet connectivity"
                ],
                correct: 1,
                explanation: "SCADA (Supervisory Control and Data Acquisition) systems are designed to control and monitor industrial processes, infrastructure, and facilities."
            },
            {
                question: "Which type of virtualization provides the strongest isolation?",
                options: [
                    "Container virtualization",
                    "Hardware virtualization (hypervisor-based)",
                    "OS-level virtualization",
                    "Application virtualization"
                ],
                correct: 1,
                explanation: "Hardware virtualization using hypervisors provides the strongest isolation by running guest operating systems directly on virtualized hardware."
            },
            {
                question: "What is a major security concern with public cloud services?",
                options: [
                    "Higher costs",
                    "Lack of control over physical infrastructure",
                    "Slower performance",
                    "Limited scalability"
                ],
                correct: 1,
                explanation: "A major concern with public cloud services is the lack of direct control over physical infrastructure and security controls managed by the cloud provider."
            },
            {
                question: "Which cloud service model requires the least management from the customer?",
                options: [
                    "IaaS",
                    "PaaS",
                    "SaaS",
                    "FaaS"
                ],
                correct: 2,
                explanation: "SaaS (Software as a Service) requires the least customer management as the cloud provider handles all infrastructure, platform, and application management."
            },
            {
                question: "What is the purpose of a cloud access security broker (CASB)?",
                options: [
                    "To provide cloud storage",
                    "To monitor and secure cloud service usage",
                    "To manage cloud costs",
                    "To backup cloud data"
                ],
                correct: 1,
                explanation: "CASB tools monitor and secure cloud service usage, providing visibility, compliance, data security, and threat protection for cloud applications."
            },
            {
                question: "Which component is typically NOT found in industrial control systems?",
                options: [
                    "PLCs (Programmable Logic Controllers)",
                    "SCADA servers",
                    "Web browsers",
                    "RTUs (Remote Terminal Units)"
                ],
                correct: 2,
                explanation: "Web browsers are typically not found in traditional ICS environments, which traditionally used specialized HMI systems rather than web interfaces."
            },
            {
                question: "What is the primary benefit of using containers in cloud environments?",
                options: [
                    "Better isolation than virtual machines",
                    "Faster deployment and resource efficiency",
                    "Enhanced security",
                    "Lower cost"
                ],
                correct: 1,
                explanation: "Containers provide faster deployment, better resource efficiency, and easier scalability compared to traditional virtual machines."
            },
            {
                question: "Which security challenge is unique to ICS/SCADA systems?",
                options: [
                    "Lack of encryption",
                    "Legacy systems and safety considerations",
                    "Insufficient bandwidth",
                    "Complex user interfaces"
                ],
                correct: 1,
                explanation: "ICS/SCADA systems often use legacy systems with long lifecycles and have safety considerations that complicate security implementations."
            },
            {
                question: "What is cloud sprawl?",
                options: [
                    "Rapid expansion of cloud services",
                    "Uncontrolled proliferation of cloud services without proper management",
                    "Performance degradation in cloud",
                    "Cloud service consolidation"
                ],
                correct: 1,
                explanation: "Cloud sprawl occurs when organizations have unmanaged proliferation of cloud services across departments, leading to security and compliance risks."
            },
            {
                question: "Which cloud model combines public and private cloud characteristics?",
                options: [
                    "Multi-cloud",
                    "Hybrid cloud",
                    "Community cloud",
                    "Private cloud"
                ],
                correct: 1,
                explanation: "Hybrid cloud combines public and private cloud characteristics, allowing workloads to move between the two environments as needed."
            },
            {
                question: "What is a PLC in industrial control systems?",
                options: [
                    "Programmable Logic Controller",
                    "Process Logic Circuit",
                    "Power Line Communication",
                    "Public Local Controller"
                ],
                correct: 0,
                explanation: "PLC (Programmable Logic Controller) is an industrial digital computer designed for controlling manufacturing processes and electromechanical operations."
            },
            {
                question: "Which approach best secures legacy ICS systems?",
                options: [
                    "Replace all legacy systems immediately",
                    "Implement network segmentation and compensating controls",
                    "Disable all network connections",
                    "Use only encrypted communications"
                ],
                correct: 1,
                explanation: "For legacy ICS systems, network segmentation and compensating controls are often the most practical approach to improve security without disrupting operations."
            },
            {
                question: "What is the primary purpose of a cloud migration strategy?",
                options: [
                    "To increase IT costs",
                    "To systematically move applications and data to cloud environments",
                    "To reduce security controls",
                    "To eliminate the need for IT staff"
                ],
                correct: 1,
                explanation: "Cloud migration strategies provide systematic approaches for moving applications, data, and infrastructure to cloud environments while minimizing risks."
            },
            {
                question: "Which factor makes ICS security more challenging than IT security?",
                options: [
                    "Higher budgets",
                    "Real-time requirements and safety systems",
                    "Better trained staff",
                    "Standardized protocols"
                ],
                correct: 1,
                explanation: "ICS security is more challenging due to real-time operational requirements and safety systems that cannot be easily taken offline for security updates."
            },
            {
                question: "What is serverless computing?",
                options: [
                    "Computers without servers",
                    "Cloud service where provider manages infrastructure, customer manages code",
                    "Free cloud computing services",
                    "Computing without internet connectivity"
                ],
                correct: 1,
                explanation: "Serverless computing allows developers to focus on code while the cloud provider manages all infrastructure, scaling, and runtime environments."
            },
            {
                question: "Which cloud threat involves attackers gaining access to multiple cloud environments?",
                options: [
                    "Cloud account takeover",
                    "Cross-cloud attack",
                    "Cloud misconfiguration",
                    "Insufficient due diligence"
                ],
                correct: 1,
                explanation: "Cross-cloud attacks involve attackers compromising multiple cloud environments, often through shared credentials or vulnerable configurations."
            },
            {
                question: "What is the main benefit of using a hyperconverged infrastructure?",
                options: [
                    "Higher costs",
                    "Simplified management and scaling",
                    "Better security",
                    "Faster internet speeds"
                ],
                correct: 1,
                explanation: "Hyperconverged infrastructure simplifies management and scaling by integrating compute, storage, and networking in modular building blocks."
            },
            {
                question: "Which principle should guide ICS network security design?",
                options: [
                    "Maximum connectivity",
                    "Defense in depth with network segmentation",
                    "Single security perimeter",
                    "Open access for efficiency"
                ],
                correct: 1,
                explanation: "ICS network security should use defense in depth with proper network segmentation to protect critical systems while maintaining operational requirements."
            },
            {
                question: "What is container orchestration?",
                options: [
                    "Managing containers manually",
                    "Automating deployment, scaling, and management of containers",
                    "Creating container images",
                    "Monitoring container performance"
                ],
                correct: 1,
                explanation: "Container orchestration automates the deployment, scaling, and management of containerized applications, with Kubernetes being the most popular platform."
            },
            {
                question: "Which cloud security framework provides comprehensive guidance?",
                options: [
                    "Only cloud provider guidelines",
                    "Industry frameworks like CSA CCM and NIST SP 800-144",
                    "No specific frameworks exist",
                    "Only regulatory compliance requirements"
                ],
                correct: 1,
                explanation: "Industry frameworks like CSA Cloud Controls Matrix (CCM) and NIST SP 800-144 provide comprehensive guidance for cloud security implementation."
            },
            {
                question: "What is the primary security concern with multi-cloud strategies?",
                options: [
                    "Higher costs",
                    "Complexity in managing security across different platforms",
                    "Slower performance",
                    "Vendor lock-in"
                ],
                correct: 1,
                explanation: "Multi-cloud strategies create complexity in managing consistent security policies and controls across different cloud provider platforms."
            },
            {
                question: "Which approach best protects sensitive data in cloud environments?",
                options: [
                    "Trust the cloud provider",
                    "Encrypt data before uploading and manage keys independently",
                    "Use only public cloud services",
                    "Avoid cloud computing entirely"
                ],
                correct: 1,
                explanation: "Encrypting data before cloud upload and maintaining independent key management provides the best protection for sensitive data in cloud environments."
            },
            {
                question: "What is the main purpose of an HMI in ICS environments?",
                options: [
                    "Human-Machine Interface for monitoring and control",
                    "High-speed Memory Interface",
                    "Hardware Management Interface",
                    "Host Monitoring Interface"
                ],
                correct: 0,
                explanation: "HMI (Human-Machine Interface) provides the operator interface for monitoring and controlling industrial processes in ICS environments."
            }
        ]
    }
};

const quizDatabaseD4 = {
    d4q1: {
        title: "Domain 4 Quiz 1: Monitoring and SIEM",
        questions: [
            {
                question: "What is the primary function of a Security Information and Event Management (SIEM) system?",
                options: [
                    "Prevent network attacks",
                    "Collect, correlate, and analyze security events from multiple sources",
                    "Encrypt network communications",
                    "Manage user passwords"
                ],
                correct: 1,
                explanation: "SIEM systems collect, correlate, and analyze security events and logs from multiple sources to detect threats and provide security monitoring."
            },
            {
                question: "Which log source is most critical for detecting insider threats?",
                options: [
                    "Network firewall logs",
                    "Authentication and access logs",
                    "Web server logs",
                    "DNS logs"
                ],
                correct: 1,
                explanation: "Authentication and access logs are most critical for detecting insider threats as they show user behavior and access patterns."
            },
            {
                question: "What is User and Entity Behavior Analytics (UEBA)?",
                options: [
                    "Analysis of user performance metrics",
                    "Detection of anomalous behavior using machine learning",
                    "Analysis of network traffic patterns",
                    "Monitoring of system resource usage"
                ],
                correct: 1,
                explanation: "UEBA uses machine learning and statistical analysis to detect anomalous behavior patterns that may indicate security threats."
            },
            {
                question: "Which component is essential for effective log management?",
                options: [
                    "Fast processors",
                    "Centralized log collection and storage",
                    "Large monitors",
                    "Multiple keyboards"
                ],
                correct: 1,
                explanation: "Centralized log collection and storage is essential for effective log management, enabling correlation and analysis across multiple systems."
            },
            {
                question: "What is the purpose of log correlation?",
                options: [
                    "To compress log files",
                    "To link related events across different systems",
                    "To delete old logs",
                    "To encrypt log data"
                ],
                correct: 1,
                explanation: "Log correlation links related events across different systems and time periods to provide a complete picture of security incidents."
            },
            {
                question: "Which log retention period is typically required for compliance?",
                options: [
                    "1 week",
                    "1 month",
                    "1 year or longer",
                    "Logs should be deleted immediately"
                ],
                correct: 2,
                explanation: "Most compliance frameworks require log retention periods of one year or longer to support forensic investigations and compliance audits."
            },
            {
                question: "What is the main benefit of using a centralized monitoring approach?",
                options: [
                    "Reduced hardware costs",
                    "Comprehensive threat detection across the environment",
                    "Faster internet speeds",
                    "Simplified user training"
                ],
                correct: 1,
                explanation: "Centralized monitoring provides comprehensive threat detection by correlating events across the entire IT environment."
            },
            {
                question: "Which type of data does EDR (Endpoint Detection and Response) collect?",
                options: [
                    "Network traffic only",
                    "Process activities, file changes, and network connections from endpoints",
                    "User authentication data only",
                    "Database query logs only"
                ],
                correct: 1,
                explanation: "EDR solutions collect comprehensive endpoint data including process activities, file changes, network connections, and system events."
            },
            {
                question: "What is threat hunting?",
                options: [
                    "Waiting for alerts to be generated",
                    "Proactively searching for threats that evaded security controls",
                    "Automatically blocking all network traffic",
                    "Deleting suspicious files"
                ],
                correct: 1,
                explanation: "Threat hunting is the proactive search for security threats and indicators of compromise that may have evaded automated security controls."
            },
            {
                question: "Which metric is most important for measuring SIEM effectiveness?",
                options: [
                    "Number of alerts generated",
                    "Mean time to detection (MTTD) and mean time to response (MTTR)",
                    "System uptime",
                    "User satisfaction scores"
                ],
                correct: 1,
                explanation: "MTTD and MTTR are key metrics for measuring SIEM effectiveness, showing how quickly threats are detected and responded to."
            },
            {
                question: "What is the purpose of log normalization?",
                options: [
                    "To encrypt log data",
                    "To convert different log formats into a standard format",
                    "To compress log files",
                    "To delete old logs"
                ],
                correct: 1,
                explanation: "Log normalization converts different log formats and structures into a standard format, enabling effective correlation and analysis."
            },
            {
                question: "Which approach reduces false positives in security monitoring?",
                options: [
                    "Installing more sensors",
                    "Tuning detection rules and using threat intelligence",
                    "Disabling all alerts",
                    "Using only signature-based detection"
                ],
                correct: 1,
                explanation: "Properly tuning detection rules and incorporating threat intelligence helps reduce false positives by focusing on relevant, high-risk indicators."
            },
            {
                question: "What is the primary purpose of network traffic analysis?",
                options: [
                    "To optimize network performance",
                    "To detect malicious activities and policy violations in network communications",
                    "To reduce bandwidth usage",
                    "To improve Wi-Fi signals"
                ],
                correct: 1,
                explanation: "Network traffic analysis monitors communications to detect malicious activities, data exfiltration, and policy violations."
            },
            {
                question: "Which log source provides the most visibility into user activities?",
                options: [
                    "Firewall logs",
                    "Active Directory logs",
                    "DNS logs",
                    "Router logs"
                ],
                correct: 1,
                explanation: "Active Directory logs provide comprehensive visibility into user authentication, authorization, and group membership activities."
            },
            {
                question: "What is the purpose of security orchestration?",
                options: [
                    "To automate security response workflows",
                    "To secure network orchestration protocols",
                    "To manage security certificates",
                    "To backup security configurations"
                ],
                correct: 0,
                explanation: "Security orchestration automates security response workflows, enabling rapid and consistent incident response across multiple security tools."
            },
            {
                question: "Which data source is critical for detecting data exfiltration?",
                options: [
                    "Email logs",
                    "Network traffic and data loss prevention (DLP) logs",
                    "Printer logs",
                    "Temperature sensors"
                ],
                correct: 1,
                explanation: "Network traffic and DLP logs are critical for detecting data exfiltration by monitoring outbound data flows and sensitive data transfers."
            },
            {
                question: "What is the main advantage of using machine learning in security monitoring?",
                options: [
                    "Lower cost",
                    "Ability to detect unknown threats and anomalies",
                    "Faster processing",
                    "Better documentation"
                ],
                correct: 1,
                explanation: "Machine learning can detect unknown threats and anomalous behavior patterns that signature-based systems might miss."
            },
            {
                question: "Which type of alert requires immediate human investigation?",
                options: [
                    "Informational alerts",
                    "Low-priority alerts",
                    "Critical security alerts indicating active threats",
                    "Routine maintenance alerts"
                ],
                correct: 2,
                explanation: "Critical security alerts indicating active threats require immediate human investigation to prevent or minimize potential damage."
            },
            {
                question: "What is the purpose of log parsing?",
                options: [
                    "To encrypt log data",
                    "To extract structured information from unstructured log entries",
                    "To delete old logs",
                    "To compress log files"
                ],
                correct: 1,
                explanation: "Log parsing extracts structured information from unstructured log entries, making the data suitable for analysis and correlation."
            },
            {
                question: "Which factor is most important for effective security monitoring?",
                options: [
                    "Number of security tools deployed",
                    "Quality and coverage of data sources",
                    "Size of security team",
                    "Budget allocated to security"
                ],
                correct: 1,
                explanation: "The quality and coverage of data sources is most important for effective security monitoring, as poor data quality limits detection capabilities."
            },
            {
                question: "What is the primary purpose of security dashboards?",
                options: [
                    "To replace detailed log analysis",
                    "To provide high-level visibility into security posture and threats",
                    "To generate compliance reports",
                    "To store security data"
                ],
                correct: 1,
                explanation: "Security dashboards provide high-level visibility into security posture, threat status, and key metrics for decision-making."
            },
            {
                question: "Which approach best protects log data integrity?",
                options: [
                    "Regular backups",
                    "Write-once-read-many (WORM) storage and digital signatures",
                    "Password protection",
                    "Encryption only"
                ],
                correct: 1,
                explanation: "WORM storage and digital signatures protect log data integrity by preventing unauthorized modifications and verifying authenticity."
            },
            {
                question: "What is the main benefit of using threat intelligence in monitoring?",
                options: [
                    "To increase alert volumes",
                    "To provide context and prioritize threats based on known indicators",
                    "To reduce system performance",
                    "To eliminate the need for monitoring"
                ],
                correct: 1,
                explanation: "Threat intelligence provides valuable context and helps prioritize threats based on known indicators, attack patterns, and threat actor activities."
            },
            {
                question: "Which log format is most commonly used for structured logging?",
                options: [
                    "Plain text",
                    "JSON (JavaScript Object Notation)",
                    "Binary format",
                    "XML only"
                ],
                correct: 1,
                explanation: "JSON (JavaScript Object Notation) is the most commonly used format for structured logging due to its readability and ease of parsing."
            },
            {
                question: "What is the primary goal of security monitoring operations?",
                options: [
                    "To generate as many alerts as possible",
                    "To detect and respond to security threats before they cause damage",
                    "To document all system activities",
                    "To optimize system performance"
                ],
                correct: 1,
                explanation: "The primary goal of security monitoring is to detect and respond to security threats before they can cause significant damage to the organization."
            }
        ]
    },
    d4q2: {
        title: "Domain 4 Quiz 2: Incident Response & Operations",
        questions: [
            {
                question: "What is the first phase of the incident response lifecycle?",
                options: [
                    "Detection and Analysis",
                    "Preparation",
                    "Containment",
                    "Recovery"
                ],
                correct: 1,
                explanation: "Preparation is the first phase of the incident response lifecycle, establishing plans, procedures, and resources before incidents occur."
            },
            {
                question: "Which incident response activity should occur during the containment phase?",
                options: [
                    "Root cause analysis",
                    "Isolating affected systems to prevent spread",
                    "User training",
                    "System restoration"
                ],
                correct: 1,
                explanation: "During containment, the focus is on isolating affected systems to prevent the incident from spreading and causing additional damage."
            },
            {
                question: "What is the primary goal of incident documentation?",
                options: [
                    "To assign blame for the incident",
                    "To provide legal evidence and support future improvements",
                    "To meet regulatory requirements only",
                    "To create detailed technical reports"
                ],
                correct: 1,
                explanation: "Incident documentation provides legal evidence, supports forensic analysis, and enables organizations to improve their security posture."
            },
            {
                question: "Which type of evidence requires strict chain of custody procedures?",
                options: [
                    "Network configuration files",
                    "Digital evidence from computer systems",
                    "User training records",
                    "System performance logs"
                ],
                correct: 1,
                explanation: "Digital evidence from computer systems requires strict chain of custody procedures to ensure integrity and admissibility in legal proceedings."
            },
            {
                question: "What is the purpose of post-incident activity?",
                options: [
                    "To return systems to normal operations",
                    "To review lessons learned and improve response capabilities",
                    "To document the incident for compliance",
                    "To assign responsibility for the incident"
                ],
                correct: 1,
                explanation: "Post-incident activity focuses on reviewing lessons learned, updating procedures, and improving incident response capabilities for future incidents."
            },
            {
                question: "Which factor is most important for effective incident response?",
                options: [
                    "Having the most advanced tools",
                    "Well-trained team with clear roles and procedures",
                    "Large response team size",
                    "Comprehensive documentation"
                ],
                correct: 1,
                explanation: "A well-trained team with clear roles, responsibilities, and procedures is more important than tools or team size for effective incident response."
            },
            {
                question: "What is the primary purpose of vulnerability scanning?",
                options: [
                    "To identify security weaknesses in systems and applications",
                    "To test network performance",
                    "To validate user access",
                    "To backup system configurations"
                ],
                correct: 0,
                explanation: "Vulnerability scanning identifies security weaknesses in systems and applications that could be exploited by attackers."
            },
            {
                question: "Which scanning approach provides the most comprehensive results?",
                options: [
                    "Unauthenticated scanning",
                    "Authenticated scanning with administrative credentials",
                    "External scanning only",
                    "Network scanning only"
                ],
                correct: 1,
                explanation: "Authenticated scanning provides the most comprehensive results by using administrative credentials to examine systems from an insider perspective."
            },
            {
                question: "What is the main difference between authenticated and unauthenticated scanning?",
                options: [
                    "Authenticated scanning requires credentials and provides deeper analysis",
                    "Authenticated scanning is faster",
                    "Unauthenticated scanning is more accurate",
                    "There is no difference"
                ],
                correct: 0,
                explanation: "Authenticated scanning uses credentials to access systems directly, providing deeper analysis and identifying vulnerabilities that unauthenticated scans might miss."
            },
            {
                question: "Which metric best indicates patch management effectiveness?",
                options: [
                    "Number of patches deployed",
                    "Percentage of systems with current patches",
                    "Time taken to deploy patches",
                    "Cost of patch management"
                ],
                correct: 1,
                explanation: "The percentage of systems with current patches is the key metric for patch management effectiveness, showing overall security posture."
            },
            {
                question: "What is the primary goal of patch testing?",
                options: [
                    "To verify patches install correctly",
                    "To ensure patches don't break system functionality",
                    "To document patch installation",
                    "To reduce patch deployment time"
                ],
                correct: 1,
                explanation: "Patch testing ensures that patches don't break system functionality or application compatibility before deploying to production systems."
            },
            {
                question: "Which change management principle helps prevent security incidents?",
                options: [
                    "Implementing changes as quickly as possible",
                    "Proper testing and approval before implementation",
                    "Skipping documentation for urgent changes",
                    "Implementing changes during business hours"
                ],
                correct: 1,
                explanation: "Proper testing and approval processes help prevent security incidents by ensuring changes don't introduce vulnerabilities or break systems."
            },
            {
                question: "What is the purpose of rollback procedures in change management?",
                options: [
                    "To speed up change implementation",
                    "To reverse changes if they cause problems",
                    "To document change history",
                    "To approve change requests"
                ],
                correct: 1,
                explanation: "Rollback procedures allow organizations to quickly reverse changes if they cause problems, minimizing downtime and potential security issues."
            },
            {
                question: "Which incident severity level typically requires executive notification?",
                options: [
                    "Low severity incidents",
                    "Medium severity incidents",
                    "High severity or critical incidents",
                    "All incidents require executive notification"
                ],
                correct: 2,
                explanation: "High severity or critical incidents typically require executive notification due to their potential impact on business operations and reputation."
            },
            {
                question: "What is the primary purpose of incident response communication plans?",
                options: [
                    "To reduce communication costs",
                    "To ensure timely and appropriate communication to stakeholders",
                    "To document all communications",
                    "To satisfy regulatory requirements only"
                ],
                correct: 1,
                explanation: "Communication plans ensure that the right people receive timely and appropriate information during incidents, supporting effective response coordination."
            },
            {
                question: "Which vulnerability assessment tool provides the most detailed technical information?",
                options: [
                    "Network scanners",
                    "Web application scanners",
                    "Source code analyzers",
                    "Configuration compliance tools"
                ],
                correct: 2,
                explanation: "Source code analyzers provide the most detailed technical information by examining actual code for security vulnerabilities and weaknesses."
            },
            {
                question: "What is the main benefit of automated patch deployment?",
                options: [
                    "Lower costs",
                    "Consistent and faster patch deployment with reduced human error",
                    "Better testing",
                    "Enhanced security"
                ],
                correct: 1,
                explanation: "Automated patch deployment provides consistent and faster patching while reducing human error, though proper testing remains important."
            },
            {
                question: "Which factor is most important when prioritizing vulnerabilities for remediation?",
                options: [
                    "CVSS score only",
                    "CVSS score combined with asset criticality and threat intelligence",
                    "Number of affected systems",
                    "Ease of exploitation"
                ],
                correct: 1,
                explanation: "Effective vulnerability prioritization considers CVSS scores along with asset criticality and current threat intelligence to focus on the highest risks."
            },
            {
                question: "What is the primary goal of incident response exercises?",
                options: [
                    "To test system performance",
                    "To validate and improve response procedures and team readiness",
                    "To satisfy compliance requirements",
                    "To train new team members"
                ],
                correct: 1,
                explanation: "Incident response exercises validate response procedures and improve team readiness, ensuring effective response during actual incidents."
            },
            {
                question: "Which evidence preservation step is most critical?",
                options: [
                    "Making copies of evidence",
                    "Maintaining chain of custody and integrity",
                    "Encrypting all evidence",
                    "Storing evidence in the cloud"
                ],
                correct: 1,
                explanation: "Maintaining chain of custody and evidence integrity is most critical for ensuring evidence admissibility and reliability in investigations."
            },
            {
                question: "What is the main challenge with zero-day vulnerability management?",
                options: [
                    "Detecting zero-day vulnerabilities",
                    "No patches are available for zero-day vulnerabilities",
                    "Zero-day vulnerabilities don't affect systems",
                    "Zero-day vulnerabilities are easily fixed"
                ],
                correct: 1,
                explanation: "Zero-day vulnerabilities pose challenges because no patches are available when they are discovered, requiring alternative mitigation strategies."
            },
            {
                question: "Which change type should have the most stringent approval process?",
                options: [
                    "Standard changes",
                    "Emergency changes",
                    "Normal changes",
                    "Routine changes"
                ],
                correct: 2,
                explanation: "Normal changes typically require the most stringent approval process as they involve significant modifications with potential for system impact."
            },
            {
                question: "What is the primary goal of digital forensics?",
                options: [
                    "To prevent future incidents",
                    "To collect and analyze digital evidence for investigations",
                    "To restore normal operations",
                    "To assign blame for incidents"
                ],
                correct: 1,
                explanation: "Digital forensics focuses on collecting and analyzing digital evidence to support investigations and incident response activities."
            },
            {
                question: "Which metric best measures vulnerability management effectiveness?",
                options: [
                    "Number of vulnerabilities found",
                    "Mean time to remediate vulnerabilities",
                    "Cost of vulnerability management",
                    "Number of scans performed"
                ],
                correct: 1,
                explanation: "Mean time to remediate vulnerabilities is a key effectiveness metric, showing how quickly organizations can address security risks."
            },
            {
                question: "What is the primary purpose of incident containment?",
                options: [
                    "To eliminate the threat completely",
                    "To prevent incident spread and limit damage",
                    "To restore normal operations",
                    "To investigate the root cause"
                ],
                correct: 1,
                explanation: "Incident containment focuses on preventing the incident from spreading and limiting damage while preserving evidence for investigation."
            },
            {
                question: "Which factor most influences patch deployment timing decisions?",
                options: [
                    "Patch cost",
                    "Business impact and system criticality",
                    "Number of affected systems",
                    "Vendor recommendations"
                ],
                correct: 1,
                explanation: "Business impact and system criticality most influence patch deployment timing, balancing security needs with operational requirements."
            }
        ]
    }
};

const quizDatabaseD5Extended = {
    d5q2: {
        title: "Domain 5 Quiz 2: Compliance and Training",
        questions: [
            {
                question: "What is the primary purpose of security awareness training?",
                options: [
                    "To reduce IT support tickets",
                    "To educate users about security risks and proper procedures",
                    "To meet regulatory requirements",
                    "To improve user productivity"
                ],
                correct: 1,
                explanation: "Security awareness training educates users about security risks, threats, and proper procedures to reduce human error and improve security posture."
            },
            {
                question: "Which regulation applies to organizations processing European citizens' data?",
                options: [
                    "HIPAA",
                    "PCI DSS",
                    "GDPR",
                    "SOX"
                ],
                correct: 2,
                explanation: "GDPR (General Data Protection Regulation) applies to organizations processing European Union citizens' personal data, regardless of where the organization is located."
            },
            {
                question: "What is the main focus of PCI DSS compliance?",
                options: [
                    "General data protection",
                    "Payment card data security",
                    "Healthcare data protection",
                    "Financial reporting"
                ],
                correct: 1,
                explanation: "PCI DSS (Payment Card Industry Data Security Standard) specifically focuses on securing payment card data and environments that process cardholder information."
            },
            {
                question: "Which principle is central to GDPR's data protection approach?",
                options: [
                    "Data maximization",
                    "Privacy by design and default",
                    "Data collection without consent",
                    "Unlimited data retention"
                ],
                correct: 1,
                explanation: "Privacy by design and default is a central GDPR principle, requiring organizations to build privacy protections into systems and processes from the beginning."
            },
            {
                question: "What is the primary goal of third-party risk management?",
                options: [
                    "To reduce vendor costs",
                    "To identify and mitigate security risks from external partners",
                    "To eliminate vendor relationships",
                    "To improve vendor performance"
                ],
                correct: 1,
                explanation: "Third-party risk management focuses on identifying and mitigating security risks that external vendors and partners may introduce to the organization."
            },
            {
                question: "Which document is typically required in vendor contracts for security requirements?",
                options: [
                    "User manual",
                    "Service Level Agreement (SLA) with security clauses",
                    "Marketing brochure",
                    "Financial statements"
                ],
                correct: 1,
                explanation: "SLAs with specific security clauses are typically required in vendor contracts to establish security requirements and accountability."
            },
            {
                question: "What is the purpose of security metrics in compliance programs?",
                options: [
                    "To impress senior management",
                    "To measure program effectiveness and demonstrate compliance",
                    "To reduce security costs",
                    "To meet audit requirements only"
                ],
                correct: 1,
                explanation: "Security metrics measure program effectiveness, demonstrate compliance progress, and provide data for continuous improvement and decision-making."
            },
            {
                question: "Which approach is most effective for measuring training effectiveness?",
                options: [
                    "Completion rates alone",
                    "Phishing simulation click rates and incident reduction",
                    "User feedback scores",
                    "Training duration"
                ],
                correct: 1,
                explanation: "Measuring phishing simulation click rates and security incident reduction provides concrete evidence of training effectiveness and behavior change."
            },
            {
                question: "What is the main requirement for data breach notifications under GDPR?",
                options: [
                    "Notify authorities within 72 hours",
                    "Notify within 30 days",
                    "Notify within 1 year",
                    "No notification required"
                ],
                correct: 0,
                explanation: "GDPR requires notification to supervisory authorities within 72 hours of becoming aware of a personal data breach, unless the breach poses low risk."
            },
            {
                question: "Which type of security training is most important for executives?",
                options: [
                    "Technical security training",
                    "Security awareness and governance training",
                    "Hands-on penetration testing",
                    "Programming security"
                ],
                correct: 1,
                explanation: "Executives need security awareness and governance training to understand their roles, make informed decisions, and lead security initiatives effectively."
            },
            {
                question: "What is the primary purpose of compliance monitoring?",
                options: [
                    "To punish non-compliant behavior",
                    "To ensure ongoing adherence to requirements and identify gaps",
                    "To reduce audit costs",
                    "To document all activities"
                ],
                correct: 1,
                explanation: "Compliance monitoring ensures ongoing adherence to requirements, identifies gaps, and supports continuous improvement of compliance programs."
            },
            {
                question: "Which factor is most important in vendor security assessments?",
                options: [
                    "Vendor size",
                    "Security controls and practices relevant to data protection",
                    "Vendor location",
                    "Vendor cost"
                ],
                correct: 1,
                explanation: "Security controls and practices specifically relevant to protecting the organization's data are most important in vendor security assessments."
            },
            {
                question: "What is the main challenge with compliance in cloud environments?",
                options: [
                    "Higher costs",
                    "Shared responsibility and data location complexities",
                    "Slower performance",
                    "Limited scalability"
                ],
                correct: 1,
                explanation: "Cloud compliance challenges include shared responsibility models, data location considerations, and maintaining control over compliance in outsourced environments."
            },
            {
                question: "Which metric indicates effective security awareness training?",
                options: [
                    "High training completion rates",
                    "Reduced security incidents and improved user behavior",
                    "Positive user feedback scores",
                    "Faster training completion"
                ],
                correct: 1,
                explanation: "Reduced security incidents and improved user behavior (measured through simulations and metrics) are the best indicators of effective training."
            },
            {
                question: "What is the primary focus of HIPAA compliance?",
                options: [
                    "Payment card security",
                    "Healthcare data privacy and security",
                    "General data protection",
                    "Financial data protection"
                ],
                correct: 1,
                explanation: "HIPAA (Health Insurance Portability and Accountability Act) focuses specifically on protecting healthcare data privacy and security."
            },
            {
                question: "Which approach best supports continuous compliance?",
                options: [
                    "Annual compliance audits",
                    "Automated monitoring and regular assessments",
                    "Manual documentation reviews",
                    "Quarterly reports"
                ],
                correct: 1,
                explanation: "Automated monitoring and regular assessments support continuous compliance by providing ongoing visibility and early detection of compliance gaps."
            },
            {
                question: "What is the main purpose of security awareness campaigns?",
                options: [
                    "To reduce training costs",
                    "To reinforce security messages and maintain awareness",
                    "To meet regulatory requirements",
                    "To improve system performance"
                ],
                correct: 1,
                explanation: "Security awareness campaigns reinforce security messages and maintain user awareness over time, countering forgetting and changing threat landscapes."
            },
            {
                question: "Which regulation focuses on financial data protection?",
                options: [
                    "GDPR",
                    "PCI DSS",
                    "HIPAA",
                    "SOX"
                ],
                correct: 3,
                explanation: "SOX (Sarbanes-Oxley Act) focuses on financial data protection and accuracy, requiring internal controls over financial reporting."
            },
            {
                question: "What is the primary benefit of vendor security questionnaires?",
                options: [
                    "To reduce vendor costs",
                    "To assess vendor security practices before engagement",
                    "To meet compliance requirements",
                    "To improve vendor relationships"
                ],
                correct: 1,
                explanation: "Vendor security questionnaires assess security practices before engagement, helping organizations make informed decisions about third-party risks."
            },
            {
                question: "Which factor is most important for successful compliance programs?",
                options: [
                    "Having the most comprehensive policies",
                    "Management commitment and organizational culture",
                    "Hiring compliance specialists",
                    "Implementing automated tools"
                ],
                correct: 1,
                explanation: "Management commitment and organizational culture are most important for successful compliance, as they drive behavior and resource allocation."
            },
            {
                question: "What is the main purpose of data classification in compliance?",
                options: [
                    "To organize data storage",
                    "To apply appropriate security controls based on sensitivity",
                    "To improve data access speed",
                    "To reduce storage costs"
                ],
                correct: 1,
                explanation: "Data classification applies appropriate security controls and protection measures based on data sensitivity and business value."
            },
            {
                question: "Which training method is most effective for technical security topics?",
                options: [
                    "Online videos",
                    "Hands-on labs and practical exercises",
                    "Written materials",
                    "Group discussions"
                ],
                correct: 1,
                explanation: "Hands-on labs and practical exercises are most effective for technical security topics, providing experiential learning and skill development."
            },
            {
                question: "What is the primary focus of SOX compliance?",
                options: [
                    "Data privacy",
                    "Payment security",
                    "Financial reporting accuracy and internal controls",
                    "Healthcare data protection"
                ],
                correct: 2,
                explanation: "SOX compliance focuses on financial reporting accuracy and internal controls to protect investors and ensure corporate accountability."
            },
            {
                question: "Which approach best handles compliance requirements across multiple jurisdictions?",
                options: [
                    "Implementing the strictest requirements globally",
                    "Understanding local requirements and implementing appropriate controls",
                    "Using only global standards",
                    "Ignoring local requirements"
                ],
                correct: 1,
                explanation: "Understanding local requirements and implementing appropriate controls for each jurisdiction ensures compliance while avoiding over- or under-implementation."
            },
            {
                question: "What is the main benefit of security culture in organizations?",
                options: [
                    "Reduced training costs",
                    "Users proactively following security practices and reporting issues",
                    "Better system performance",
                    "Improved vendor relationships"
                ],
                correct: 1,
                explanation: "A strong security culture results in users proactively following security practices and reporting potential issues, creating a more resilient security posture."
            },
            {
                question: "Which factor determines appropriate security training frequency?",
                options: [
                    "Regulatory requirements only",
                    "Risk level, threat landscape, and role requirements",
                    "Budget constraints",
                    "Management preferences"
                ],
                correct: 1,
                explanation: "Security training frequency should be determined by risk level, evolving threat landscape, and specific role requirements, not just regulatory minimums."
            }
        ]
    }
};

// Merge all quiz databases
Object.assign(allQuizzes, quizDatabaseD3, quizDatabaseD4, quizDatabaseD5Extended);