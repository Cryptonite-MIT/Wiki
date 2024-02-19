## **What is Cryptography**

It is the study of secure communications techniques that allow only the sender and intended recipient of a message to view its contents.

![img1](/crypto/img/Picture1.png)

Consider the following scenario where Alice wants to communicate with Bob, but doesn't want Eve to be looking at their texts. We use cryptography to encrypt the messages between Alice and Bob so that no eavesdropper like Eve can listen to their conversations.

## **Encoding and Encryption**

- Encoding is a process of putting a sequence of characters into a special format for transmission or storage purposes.
- An example of encoding is converting ASCII characters to Hex.
- ASCII: Hello Hex: 48656c6c6f
- Encryption is the process of translation of data into a secret code. Encryption is the most effective way to achieve data security. To read an encrypted file, you must have access to a secret key or password that enables you to decrypt it.
- Making the message sent by Alice to Bob unreadable by an outsider is encryption.

**Encoding**

- Base is the total number of unique elements we can use to represent data in an encoding format.
- Coming Encoding Formats:
  - ASCII - American Standard Code for Information Interchange(a-z,A-Z,0-9)
    - A-Z - 65-90
    - a-z - 97-122
    - 0-9 - 48-57
  - Binary - Base 2 (0, 1)
  - Hex - Base 16 (0-9, a-f)
  - Base 64 - (A-Z, a-z, 0-9, +, /)

**Encryption**

- Basic terms in encryption:
  - **Plain text:** The original message that is sent.
  - **Cipher text:** Encrypted form of the plain text which doesn't have any meaning or is unreadable.
  - **Key:** A key iis a piece of information, usually a string of numbers or letters, which, when processed through a cryptographic algorithm, can encrypt or decrypt cryptographic data.

![img2](/crypto/img/Picture2.png)

In the above image, Original Data is the Plaintext and the public key is used by the sender to encrypt the plaintext. Scrambled Data in picture is the ciphertext. The intended receiver has the private key and uses it to decrypt the plaintext that they receive using the private key.

## **Types of Cryptosystems**

- **Symmetric key Cryptosystems** use the same key for encryption and decryption processes.
- **Asymmetric key Cryptosystems** use different keys for encryption and decryption processes.
  - Public key is used by the sender to encrypt the data.
  - Private key is used by the intended receiver to decrypt the ciphertext

![img3](/crypto/img/Picture3.png)

## **Substitution Ciphers**

Substitution ciphers encrypt the plaintext by swapping each letter or symbol in the plaintext by a different symbol as directed by the key.

![img4](/crypto/img/Picture4.png)

In the above example, 'A' is substituted by 'D', 'B' with 'E' and so on.

**Caesar Cipher**

It is a type of substitution cipher in which each letter in the plaintext is 'shifted' a certain number of places down the alphabet.

![img5](/crypto/img/Picture5.png)

In the above example, 'd' is substituted by 'e' and 'f' is substituted 'g' and so on. After observing the above example we can see that each letter in the plaintext is shifted by one position to the right in the alphabet.

We can say that the shift key is 1 in the above example.

**Transposition Cipher**

Transposition cipher scrambles the position of characters without actually changing the original characters in the plaintext.

The plaintext is rearranged according to a regular system.

The ciphertext is a permutation of the plaintext.

**Columnar Transposition cipher**

The plaintext is written row wise with a set number of columns which is generally set as the length of the key.

The plaintext is then read column wise based on the column numbers.

The columns are usually defined by a keyword and the permutation is defined by the alphabetical order of the letters in the keyword.

Example: Consider the plaintext "hello there" and the key is "hey"

Writing the plaintext in rows:

h e l

l l o

t h e

r e x

Here 'x' is a null that is added to the matrix to completely fill up the matrix.

2 1 3

h e l

l l o

t h e

r e x

Writing the plaintext based on column number we get

**elhe hltr loex**

For decryption, we need to get the column length by dividing the message length by the key length. The message can be written out in columns and reorder the columns based by reforming the key.

## **XOR**

This is a encryption method which based on the XOR gate

![img6](/crypto/img/Picture6.png)

Since XOR is a stream cipher, the encryption takes place bitwise

- Consider 10 XOR 15
  - Convert 10 to binary =\> 1010 and convert 15 to binary =\> 1111
  - 10 XOR 15 is 1010 XOR 1111
  - 1010 XOR 1111 is 0101 which is 5

| **10** | **15** | **10 XOR 15** |
| --- | --- | --- |
| 1 | 1 | 0 |
| 0 | 1 | 1 |
| 1 | 1 | 0 |
| 0 | 1 | 1 |

**Properties of XOR:**

- XOR is Commutative and Associative:
  - a XOR b = b XOR a
  - (a XOR b)XOR c = a XOR (b XOR c)
- A XOR A = 0
- A XOR 0 = A
- If Pt XOR key = Ct then
- Pt = Ct Xor key
- key = Pt XOR Ct

**Single Byte XOR**

- The entirety of the plaintext is XORed with only a single character.
- This makes Single Byte XOR vulnerable to brute force attack.

| **Plaintext** | w | e | l | c | o | m | e |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Key** | = | = | = | = | = | = | = |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Ciphertext** | J | X | Q | ^ | R | P | X |

**MultiByte XOR**

- A key of length n is XORed with substring of plaintext of size n.
- Provides better security than single byte xor.

| **Plaintext** | W | E | L | C | O | M | E |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Key** | q | w | e | q | w | e | q |
| **CIphertext** | & | 2 | ) | 2 | 8 | ( | 4 |

**Attacks on XOR**

- **Brute Force Attack:**
  - In this approach we try out all possible keys.
  - In Single Byte XOR, if the key length is one byte i.e 8 bits which gives us 28 possibilities.
  - We XOR the ciphertext with all possible keys and find a resulting plaintext which is human readable.
- **Known Plaintext Attack:**
  - If we know a part of the plaintext, then we can XOR it with the corresponding part of the ciphertext to get the key.

## **Modular Arithmetic**

When we divide two Integers A and B, we can write the division A/B in the form: A=BQ+R

Where:

- A -\> Dividend
- B -\> Divisor
- Q -\> Quotient
- R -\> Remainder

Modulo Operator:

From the equation A=BQ+R we can get R by the following operation:

- R = A%B or R = A mod B
- Eg: 19%15 = 4

The value of R is always between 0 and B i.e 0 \<= R \< B

Modulo Inverse:

Given a modular arithmetic A mod B:

- Modular inverse of A exists on B if, A and B are co primes i.e GCD(A,B) = 1

If 1 = A\*C mod B then C is said to be the modular inverse of A on B.

## **Basic RSA**

- RSA algorithm is asymmetric cryptography algorithm.
- Asymmetric actually means that it works on two different keys i.e. Public Key and Private Key
- Public Key is given to everyone and Private key is kept private.

![img7](/crypto/img/Picture7.png)

Generating Keys in RSA:

Generating Public key:

- Select two prime numbers p,q
- n = p\*q ; n-\>modulus
- phi(n) = (p-1)\*(q-1)
- Select a integer 'e' such that GCD(e,phi(n)) = 1 and 1 \< e \< phi(n)
- Public Key: (e,n)

Generating Private key:

- Calculate value of 'd':
  - e\*d mod phi(n) = 1 i.e d = modular inverse of e on phi(n)
- Private key : (d,n)

Basic Algorithm:

Encryption:

- M -\> plaintext and M \< n
- C -\> ciphertext
- C = Me mod n

Decryption:

- M = Cd mod n