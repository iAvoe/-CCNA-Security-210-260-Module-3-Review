# CCNA-Security-210-260-Module-3-Review
### 5 - Fundamentals of VPN Technology and Cryptography
https://www.brainscape.com/flashcards/fundamentals-of-vpn-technology-and-crypt-6435350/packs/10114503

**What algorithms in a VPN provide the confidentiality?** (Multiple choice)

    a. MD5
    b. SHA-1
    c. √ AES
    d. √ 3DES

**A remote user needs to access corporate network from hotel room on a laptop shall use which type of VPN?**

    a. Site-to-site VPN
    b. Dial-up VPN
    c. PPP VPN
    d. √ Remote-access VPN

**Which type of VPN technology is likely to be used in a site-to-site VPN?**

    a. SSL
    b. TLS
    c. HTTPS
    d. √ Ipsec

**Which are the following are benefits of VPNs?** (Multiple choice)

    a. Hashing
    b. √ Confidentiality
    c. Diffie-Hellman
    d. √ Data integrity
    e. √ Authentication
    f. √ Transposition

**Which of the following are symmetrical encryption ciphers?** (Multiple choice)

    a. SHA1
    b. √ AES
    c. RSA
    d. √ 3DES

**What is the primary difference inbetween a hash & Hashed Message Authentication Code (HMAC)?**

    a. √ Keys
    b. MD5
    c. SHA1
    d. AES

**What is used to encrypt the hash in a digital signature?**

    a. Sender’s public key
    b. √ Sender’s private key
    c. Receiver’s public key
    d. Receiver’s private key

**What are valid options to protect data in motion with/without a full VPN?** (Multiple choice)

    a. √ TLS
    b. √ SSL
    c. √ HTTPS
    d. √ IPsec

**Why is the public key in a typical public-private key pair referred to as public?**

    a. Because the public already has it.
    b. √ Because it is shared publicly.
    c. Because it is a well-known algorithm that is published.
    d. The last name of the creator was publica, which is Latin for public

**Which key component is used to create digital signatures?**

    a. Ink
    b. Public key
    c. √ Private key
    d. AES

**Which key component is used to verify digital signatures?**

    a. √ Sender’s public key
    b. Receiver’s public key
    c. AES
    d. One-time PAD

**What is another name for a hash that has been encrypted with a private key?**

    a. MD5
    b. SHA-1
    c. AES
    d. Digital signature

**What are the primary responsibilities for a certificate authority (CA)?** (Multiple choice)

    a. Verification of certificates
    b. √ Issuing identity certificates
    c. Maintaining client’s private keys
    d. Tracking identity certificates

**Which one is not a way for a client to learn whether a certificate has been revoked?**

    a. Look at the lifetime of the certificate itself
    b. √ CRL
    c. √ OSCP
    d. √ LDAP

**Which item(s) are found in a typical identity certificate?** (Multiple choice)

    a. √ CRL locations
    b. √ Validity date
    c. √ Public key of the certificate owner
    d. √ Serial number

**Which standard format is used to request a digital certificate from a CA?**

    a. PKCS#7
    b. √ PKCS#10
    c. LDAP
    d. TLS/SSL/HTTPS

**Explain PKCS#10**:

    -. A certificate request format sent to CA that wants to receive its identity certificate.
    -. Requires public key for the entry desiring a certificate
    
**Explain PKI topology**:

    -. PKIs can form different topologies of trust
    -. In singular model, a single CA / root CA issues all the certificates to the end users
    -. In Siabardinele model, CAs can issue certificates to both end users & subordinate CAs (thus elect sub-CAs to become valid issuer)

**When obtaining the initial root certificate, what method should be used for validation of the certificate?**

    a. Sender’s public key
    b. √ Telephone
    c. HTTPS/TLS/SSL
    d. Receiver’s private key

**List root certificate components**:

    -. Serial number
    -. Issuer
    -. Validity dates
    -. Subject
    -. Public key
    -. Thumbprint algorithm & thumbprint data
    -. CRL Location

**Explain X.509 & X.509v3 certificates**

    -. A series of standards focused on directory services & how those directory services are organized

**Simplest method to use when implementing identity certificates on the client (supported by both client & CA)?**

    a. PKCS#7
    b. PKCS#10
    c. √ SCEP
    d. LDAP

**List 3 types of VPNs?**: IPSec, SSL, MPLS

**Explain IPSec-based VPNs**: Layer 3 security method, supports site-to-site & remote-access VPN application

**Explain SSL-based VPNs**: TCP session security (over layer 6 encrypted SSL tunnels), can be used for remote-access VPN, https applications

**Explain MPLS-based VPNs**: Multiprotocol Label Switching (MPLS) VPN suppoers point-to-point, layer 2 (VPLS/'switch-in-cloud"), & layer 3 (virtual routing & forwarding - VPRN / VPLS with routing). Supports best with site-to-site, multi-site application

**Review: list symmetric, asymmetric & hashing algorithms separately**:

    - Symmetric: DES, 3DES, AES, IDEA, RC2/3/4/5/6, Blowfish
    - Asymmetric: RSA, DH, ElGamal, DSA, ECC
    - Hashing: MD5, SHA, SHA2

**Review: list HMAC components**: hash string & secret key

**Review: list benefits of digital signatures**: Authentication; Data integrity; Nonrepudation



### 6 - Fundamentals of IP Security
https://www.brainscape.com/flashcards/fundamentals-of-ip-security-6435415/packs/10114503

**Which technology is a primary method that IPsec uses to implement data integrity?**

    a. √ MD5
    b. AES
    c. RSA
    d. DH

**What are the source, destination addresses used for encrypted IPsec packets?**

    a. Original sender and receiver IP addresses
    b. Original sender’s and outbound VPN gateway’s addresses
    c. √ Sending and receiving VPN gateways
    d. Sending VPN gateway and original destination address in the packet

**Which phase is used for private management traffic between the two VPN peers?**

    a. IPsec
    b. √ IKE Phase 1
    c. IKE Phase 2
    d. IKE Phase 3

**What are negotiated during IKE Phase 1?** (Multiple Choice)

    a. √ Hashing
    b. √ DH group
    c. √ Encryption
    d. √ Authentication method

**Which methods are used to allow 2 VPN peers to establish shared secret keys over an untrusted network?**

    a. AES
    b. SHA
    c. RSA
    d. √ Diffie-Hellman (DH)

**Which of the following is not part of IKE Phase 1?** (Multiple Choice)

    a. √ Negotiation of the IKE Phase 1 protocols
    b. √ Running DH
    c. √ Authenticating the peer
    d. Negotiating the transform set to use

**How is the negotiation of the IPsec (IKE Phase2) tunnel done securely?**

    a. √ Uses the IKE Phase 1 tunnel
    b. Uses the IPsec tunnel
    c. Uses the IKE Phase 2 tunnel
    d. Uses RSA

**Which main methods authenticate a peer as the last step of IKE Phase 1?** (Multiple Choice)

    a. √ RSA signatures, using digital certificates to exchange public keys
    b. √ PSK (pre-shared key)
    c. DH Group 2
    d. TCP three-way handshake

**Which component acts as an if-then statement looks for packets that should be encrypted before leaving an interface?**

    a. crypto isakmp policy
    b. √ crypto map
    c. crypto ipsec transform-set
    d. crypto access-list (access list used for cryptography)

**Which symmetrical algorithms & symmetrical crypto ACLs on VPN peers is true?**

    a. √ Symmetrical algorithms use the same secret (key) to lock and unlock the data. Symmetrical ACLs between two VPN peers should symmetrically swap the source and destination portions of the ACL.
    b. Symmetrical algorithms like RSA use the same secret (key) to lock and unlock the data. Symmetrical ACLs between two VPN peers should symmetrically swap the source and destination portions of the ACL.
    c. Symmetrical algorithms use the same secret (key) to lock and unlock the data. Symmetrical ACLs between two VPN peers should be identical.
    d. Symmetrical algorithms use the same secret (key) to lock and unlock the data. Symmetrical ACLs between two VPN peers require that only symmetrical algorithms be used for all aspects of IPsec.

**Which command reveal the ACLs, transform sets, peer information & indicate the interface used to connect to remote IPsec VPN peer?**

    a. √ show crypto map
    b. show crypto isakmp policy
    c. show crypto config
    d. show crypto ipsec sa
