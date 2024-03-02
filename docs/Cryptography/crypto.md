# Baby RSA
## Description
RSA is for babies. So we improved it by taking it to the next dimension.

## Solution
Putting `n` in dcode.fr gives `p` and `q`:
```
p = 142753777417406810805072041989903711850167885799807517849278708651169396646976000865163313860950535511049508198208303464027395072922054180911222963584032655378369512823722235617080276310818723368812500206379762931650041566049091705857347865200497666530004056146401044724048482323535857808462375833056005919409
q = 161374151633887880567835370500866534479212949279686527346042474641768055324964720409600075821784325443977565511087794614167314642076253331252646071422351727785801273964216434051992658005517462757428567737089311219316483995316413254806332369908230656600378302043303884997949582553596892625743238461113701189423
```
<br>
Reference for matrix RSA decryption:
https://www.researchtrend.net/ijet/pdf/13%20%20Matrix%20Modification%20of%20RSA%20Public%20Key%20Cryptosystem%20and%20its%20Variant%20Manju%20Sanghi%203513.pdf <br>

```py
phi = (p**2 -1)*(q**2 - 1)
d = pow(e, -1, phi)

#ct contains the given ciphertext output
c = matrix(Zmod(n), [[ct[0], ct[1]], [ct[2], ct[3]]])
pt = c ^ d

flag = b''
for row in pt:
    for ele in row:
        flag += long_to_bytes(int(ele))
print(flag)
```
## Flag
`BITSCTF{63N3r41_11N34r_6r0UP_C4ND0_4NY7H1N6}`






# Not Suspicious Agency

## Description
The Not Suspicous Agency has created a very secure way to encrypt your messages that only trusted individuals can decrypt. Trust is very important after all.

## Solution
Reference for Dual_EC_DRBG:
https://www.youtube.com/watch?v=nybVFJVXbww <br><br>
`P` and `Q` are  nistp256 points. `e` referenced in the video is what we have in `backdoor.txt`. We can check that `Q = eP`. So, we recover `rQ` by bruteforce, and multiply it by inverse of `e` to get the state `s`. <br><br>
```einv * (r * Q) = einv * (r * e * P) = einv * e * (rP) = rP and s = rP.x```
<br><br>

```py
def find_y_square(x):
    a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    y2 = (pow(x, 3, p) + a * x + b) % p
    return y2

e = 106285652031011072675634249779849270405
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

trunc_rQ = strxor(test_op, test_str)[:30]

flag = False
for i in range (256):
    for j in range (256):
        b1 = long_to_bytes(i)
        b2 = long_to_bytes(j)
        rQx = bytes_to_long(b1 + b2 + trunc_rQ)
        ysq = int(find_y_square(int(rQx)))
        try:
            y = pow(ysq, (p + 1) // 4, p)
            Z = ECC.EccPoint(rQx, y, curve='p256')
            einv = pow(e, -1, n)
            rP = einv * Z
            s2 = int(rP.x)
            g2 = generate(P, Q, s2)
            pt = encrypt(g2, test_op[-5:])
            if pt == b'gging':
                print(pt)
                pt = encrypt(g2, flag_op)
                print(pt)
                flag = True
        except:
            pass
        if flag:
            break
    if flag:
        break
if not flag:
    print("not found")
```

## Flag
`BITSCTF{N3V3r_811ND1Y_7rU57_574ND4rD5}`
