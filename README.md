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

**Explain Hashed Message Authentication Code (HMAC)**: secret key based hashing authentication, cannot perform hashing without key

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


**Explain PKCS#7**: The certificate itself in response of PKCS#10

**Explain PKCS#10**:

    - A certificate request format sent to CA that wants to receive its identity certificate.
    - Requires public key for the entry desiring a certificate
    
**Explain PKCS#12**:

    - A file that stores public & private keys pritected by a symmetric password
    
**Explain PKI topology**:

    - PKIs can form different topologies of trust
    - In singular model, a single CA / root CA issues all the certificates to the end users
    - In Siabardinele model, CAs can issue certificates to both end users & subordinate CAs (thus elect sub-CAs to become valid issuer)

**When obtaining the initial root certificate, what method should be used for validation of the certificate?**

    a. Sender’s public key
    b. √ Telephone
    c. HTTPS/TLS/SSL
    d. Receiver’s private key

**List root certificate components**:

    - Serial number
    - Issuer
    - Validity dates
    - Subject
    - Public key
    - Thumbprint algorithm & thumbprint data
    - CRL Location

**Explain X.509 & X.509v3 certificates**

    - A series of standards focused on directory services & how those directory services are organized

**Simplest method to use when implementing identity certificates on the client (supported by both client & CA)?**

    a. PKCS#7
    b. PKCS#10
    c. √ SCEP
    d. LDAP

**Explain cipher & cipher types**:

    - The string used for encryption & decryption
    - Substitution: replace characters with other characters, but keeps their original position
    - Polyalphabetic: using multiple substitution possibility to enhance substitution cipher
    - Transposition: reposition of charachers, but the characters are the same
    

**Review: Explain block & stream ciphers**:

    - block: a symmetric key cipher that operates on a bit-block spanning on multiple charachers
    - stream: the cipher that encrypts 1 bit / character at a time
    - The block cipher has more overhead

**List 3 types of VPNs**: IPSec, SSL, MPLS

**Explain IPSec-based VPNs**:

    - Layer 3 security method
    - supports site-to-site & remote-access VPN
    - provides confidentiality by encrypting
    - provides data integrity through HMAC & hashing
    - provides authentication via digital signatures or pre-shared key

**Explain SSL-based VPNs**: TCP session security (over layer 6 encrypted SSL tunnels), can be used for remote-access VPN, https applications. Every web browser supports SSL makes it available for everyone

**Explain MPLS-based VPNs**: Multiprotocol Label Switching (MPLS) VPN suppoers point-to-point, layer 2 (VPLS/'switch-in-cloud"), & layer 3 (virtual routing & forwarding - VPRN / VPLS with routing). Supports best with site-to-site, multi-site application

**Review: list symmetric, asymmetric & hashing algorithms separately**:

    - Symmetric: DES, 3DES, AES, IDEA, RC2/3/4/5/6, Blowfish
    - Asymmetric: RSA, DH, ElGamal, DSA, ECC
    - Hashing (popular types): MD5, SHA, SHA2

**Review: Explain what is hashing**:

    - a one-way algorithm to verify data intergrity (hash string can only be produced by data block)
    - by taking blocks of data and create a small fixed size hash string
    - the same data will produce the same hash string

**Review: which algorithm is the faster**: symmetric algorithm is faster than asymmetric

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

### 7 - Implementing IPsec Site-to-Site VPNs
https://www.brainscape.com/flashcards/implementing-ipsec-site-to-site-vpns-6438431/packs/10114503

**Which could be part of both an IKEv1 Phase 1 and IKEv1 Phase 2 policy?** (Multiple Choice)

    a. √ MD5
    b. √ AES
    c. RSA
    d. √ DH

**How is it possible that a packet with private L3 destination address is forwarded over Internet?**

    a. √ It's encapsulated into another packet, and Internet only sees the outside valid IP destination address.
    b. It cannot be sent. It will always be dropped.
    c. The Internet does not filter private addresses, only some public addresses, based on policy.
    d. NAT is used to change the destination IP address before the packet is sent.

**What is the method for specifying the IKEv1 Phase 2 encryption method?**

    a. Crypto ACLs
    b. crypto isakmp policy
    c. √ crypto ipsec transform-set
    d. RSA signatures

**Which one potentially could be negotiated during IKEv1 Phase 2?** (Multiple Choice)

    a. √ Hashing
    b. √ DH group
    c. √ Encryption
    d. Authentication method

**Which of the DH groups is the most prudent to use when security is of the utmost importance?**

    a. 1
    b. 2
    c. √ 5
    d. 6

**Which are not part of an IKEv1 Phase 2 process?** (Multiple Choice)

    a. Main mode
    b. √ Specifying a hash (HMAC)
    c. √ Running DH (PFS)
    d. √ Negotiating the transform set to use

**Which encryption method will be used to protect the negotiation of the IPsec (IKEv1 Phase 2) tunnel?**

    a. The one negotiated in the transform set.
    b. The one negotiated for the IKEv1 Phase 2 tunnel.
    c. √ The one negotiated in the ISAKMP policy.
    d. There is no encryption during this time; that is why DH is used.

**Which is the most secure method for authentication of IKEv1 Phase 1?**

    a. √ RSA signatures, using digital certificates to exchange public keys
    b. PSK
    c. DH group 5
    d. Symmetrical AES-256

**Which component is not placed directly in a crypto map?**

    a. √ Authentication policy
    b. ACL
    c. Transform set
    d. PFS

**Which one would cause a IPsec VPN tunnel never initializes / works?** (Multiple Choice)

    a. √ Incompatible IKEv1 Phase 2 transform sets
    b. Incorrect pre-shared keys or missing digital certificates
    c. Lack of interesting traffic
    d. Incorrect routing

**Which one IKE versions are supported by the Cisco ASA?** (Multiple Choice)

    a. √ IKEv1
    b. √ IKEv2
    c. √ IKEv3
    d. √ IKEv4

**What is NAT exemption for?**

    a. To bypass NAT in the remote peer
    b. To bypass NAT for all traffic not sent over the IPsec tunnel
    c. √ To bypass NAT for traffic in the VPN tunnel
    d. To never bypass NAT in the local or remote peer

**Which one commands are useful when troubleshooting VPN problems in the Cisco ASA?** (Multiple Choice)

    a. √ show isakmp sa detail
    b. √ debug crypto ikev1 | ikev2
    c. √ show crypto ipsec sa detail
    d. √ show vpn-sessiondb

**The Cisco ASA CANNOT be configured with more than one IKEv1 or IKEv2 policy**: False
