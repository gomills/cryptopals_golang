These are notes and instructions that explain each CryptoPals challenge. As of last update, I've completed up to set 3.

# Summary of vulnerabilites studied

This is a summary! You won't understand anything unless you've read the theory.

AES: this is a block cipher and it has no inherent vulnerabilities. Vulnerabilities come from the mode chosen and its implementation.

### XOR-based schemes

- **Single-byte XOR**
  - Trivial to recover by brute-forcing all 256 keys and scoring results with English frequency models.
- **Repeating-key XOR (Vigenère-style)**
  - Key reuse creates periodic statistical structure.
  - Typical method:
    1. Estimate key length via normalized Hamming distance between ciphertext blocks.
    2. Transpose bytes by key position.
    3. Solve each column as a single-byte XOR (frequency scoring / brute force).

---

### AES-ECB

- **Property:** deterministic & stateless — identical plaintext blocks → identical ciphertext blocks.
- **Leak:** exposes block-level patterns (visual/textual structure).
- **Attacks / techniques used**
  - _Mode detection_ — find repeated ciphertext blocks on repeated-input plaintexts.
  - _Byte-at-a-time decryption (known alignment)_ — prepend chosen bytes so unknown byte aligns in a block; brute-force match.
  - _Byte-at-a-time with unknown random prefix_ — use duplicated-block sentinel to find alignment, then proceed.
  - _Cut-and-paste (block splicing)_ — rearrange/substitute ciphertext blocks to craft desired plaintext fields (e.g., `role=admin`).

---

### AES-CBC

- **Property:** `P[n] = Dec(C[n]) ⊕ C[n-1]` — flipping bits in `C[n-1]` flips corresponding bits in `P[n]`.
- **Uses / attacks**
  - _Bit-flip injection_ — edit plaintext values by targeted bit flips in previous block (useful for tampering, not direct decryption).
  - _Padding-oracle_ — if a PKCS#7 validator reveals valid/invalid padding, decrypt block-by-block by manipulating `C[n-1]` and observing responses.

---

### AES-CTR (stream mode)

- **Property:** produces a keystream; ciphertext = plaintext ⊕ keystream.
- **Critical failure:** reusing nonce/key → identical keystream across messages.
- **Consequence:** keystream reuse reduces CTR to a many-time pad; attackable like repeating-key XOR (crib-dragging, statistical recovery).

# Random, handy Golang notes

$randint[5,10]=rand[0,5] + 5$

Byte casting byte(x) keeps only the last 8 bits! To divide a number into bytes, just use the binary library. E.g

```go
	var rand uint32
	keystreamBytes := make([]byte, 4)
	for n := range stream {

		// 1.1 Get current keystream, once all 4 bytes from the last were consumed or when starting out
		r := n % 4
		if r == 0 {
			rand = gen.Rand()
			binary.LittleEndian.PutUint32(keystreamBytes, rand)
		}

		// 2.3 Encrypt / decrypt
		result[n] = stream[n] ^ keystreamBytes[r]
	}
```

# 1. Challenge 1

We have to perform an encoding change. We'll be using hexadecimal and Base64 encoding. Now that we're working with Base64 and Hex we'll take advantage of it to write both functions of encoding and decoding even though we'll just use on of each. They will be handy later on.

## Hexadecimal

Hexadecimal encoding represents bytes using 16 characters: `[0–9]` and `[A–F]`.  
Each hexadecimal digit encodes **4 bits** (half a byte), because $1111_2 = 15$ and $0000_2 = 0$. Therefore, this is very important and makes hex predictable: two hex characters represent 1 byte.

We can think of it as a direct mapping between numeric values $[0,15]$ and their symbols:

$$
\begin{array}{c|cccccccccccccccc}
\text{Decimal} & 0 & 1 & 2 & 3 & 4 & 5 & 6 & 7 & 8 & 9 & 10 & 11 & 12 & 13 & 14 & 15 \\
\hline
\text{Hex} & 0 & 1 & 2 & 3 & 4 & 5 & 6 & 7 & 8 & 9 & A & B & C & D & E & F
\end{array}
$$

Because 4 bits can represent values from `0000` ($0$) to `1111` ($15$), one hex digit perfectly fits one nibble (half byte).  
If we used 5 bits, we’d have $2^5 = 32$ possible values — but only 16 characters — so the mapping would break.  
Therefore, **every two hex characters correspond to one byte**.

### Bitwise operators in Go (inherited from C)

Bitwise operators let us manipulate individual bits inside bytes:

- **AND** (`&`): keeps bits that are `1` in both operands.  
  Example: $(10110110_2 \,\&\, 00001111_2) = 00000110_2$

- **OR** (`|`): keeps bits that are `1` in either operand.  
  Example: $(00000001_2 \,|\, 00000100_2) = 00000101_2$

- **XOR** (`^`): toggles bits that differ between operands. Same as AND but if they're the same we negate.
  Example: $(1100_2 \oplus 1010_2) = 0110_2$

- **NOT**: flips all bits. Same as **XOR** but without the left byte, ^to_xor_byte.
  Example: $\sim 00001111_2 = 11110000_2$

- **Shifts** (`<<`, `>>`): move bits left or right by _n_ positions.  
  Example: $(00000001_2 << 3) = 00001000_2$

### Hex decoding algorithm (Go)

1. Prepare a **map string** containing all hexadecimal characters in order (e.g. `"0123456789abcdef"`).

   - This provides implicit indices: `'a'` maps to `10`, `'f'` to `15`, etc.

2. Validate the encoded string:

   - If its length is not a multiple of `2`, the input is **corrupt**.

3. Preallocate a decoded byte array with length `len(encoded)/2`.

4. Iterate over the encoded string **in pairs of characters**:
   1. Take the first character of the pair.
      - Convert it to its integer value by finding its index in the map string.
      - Shift that integer **4 bits to the left** (it will occupy the high nibble).
   2. Take the second character of the pair.
      - Convert it to its integer value (no shift; it stays in the low nibble).
   3. Combine both nibbles using a **bitwise OR**.
   4. Store the resulting byte into the decoded array at the corresponding index.

**Note:** The algorithm is deterministic and the output length is known beforehand. Avoid appending at all costs, memory reallocation is expensive AF.

---

### Hex encoding algorithm (Go)

1. Preallocate an encoded byte array of length `len(input) * 2`.

   - Each byte expands into two hexadecimal characters.

2. Iterate over every byte in the input slice:
   1. Extract the **high nibble** by shifting the byte **4 bits to the right**.
   2. Extract the **low nibble** by performing a bitwise **AND** with `$00001111_2$`.
   3. For each nibble:
      - Use it as an index in the map string (`"0123456789abcdef"`) to get its corresponding character.
      - Write each character sequentially into the encoded array.

## Base64

Base64 encoding uses 64 distinct characters. It’s trickier than hexadecimal since it operates on **6-bit groups** rather than 8-bit bytes. Every 3 bytes (3 × 8 = 24 bits) are split into 4 groups of 6 bits each:

$$
3 \text{ bytes} \times 8 \text{ bits} = 24 \text{ bits} \Rightarrow \frac{24}{6} = 4 \text{ base64 characters}
$$

each with two leading zeroes.

This is very important, it makes base64 predictable: every 4 encoded bytes we have 3 decoded bytes (wether they're artificial or not due to padding we'll see later...)

Therefore, the encoded string must have a length that is a multiple of 4. If not, the data is either corrupt or not Base64-encoded.

Because 3 bytes don’t always divide evenly, Base64 relies on **padding**. Padding ensures the total bit length is a multiple of 24 and signals that the last group contains extra, artificial bits.

- If 1 byte is missing, add one zero byte of padding.  
  The sequence becomes:  
  `byte1 byte2 byte00 → e_b1 e_b2 e_b3 e_b4`  
  Here, `e_b3` contains two 0 bits from the padding, and `e_b4` is entirely padding.  
  Replace `e_b4` with `=` in the final string.

- If 2 bytes are missing, add two zero bytes of padding.  
  The last two encoded bytes are padding and become `==`.

When decoding, a trailing `=` means one fewer byte of actual data, and `==` means two fewer. In implementation, this can simplify the logic: during the last iteration, if padding symbols appear, simply skip writing bytes past the preallocated range, without even considering if we have $=$ or not.

### Base64 decoding algorithm

1. If the input length is not a multiple of 4 → corrupt.
2. Preallocate a decoded buffer of length:
   $$
   \text{decoded\_length} = \frac{3}{4} \times \text{encoded\_length}
   $$
3. Process 4 characters at a time.
4. Convert each Base64 character to its 6-bit value using the decoding map: each has two trailing zeroes, so they're virtually 6 bits bytes and they'll map gracefully
5. Recombine each group of 4×6 bits into 3 bytes using shifts and masks.
6. If `=` is found, substitute with zero and avoid writing the artificial bits to the decoded string

Here's an example:

Let’s illustrate the case when the **last group** ends with a single `=`.  
That means **2 full bytes** of data were encoded, and the **third byte** was padded.

#### Example input group:

```
e_b1  e_b2  e_b3  "="
```

---

#### Step 1. Base64 6-bit values (each from lookup)

Thanks to padding we know that ch3 only contains 4 real bits; its last two and the whole ch4 is artificial

```
ch1   ch2   ch3   ch4
[00aaaaaa][00bbbbbb][00cccccc][00000000]   ← ch4 = 0 because '='
```

#### Step 2. Bit alignment and extraction into bytes

We know that we have only two real bytes, so the last one will be artificial

```
  byte1: aaaaaabb
  byte2: bbbbcccc
  byte3: cc000000   ← padded bits. Here last two cc are 0's
```

So effectively:

```
byte1 = (ch1 << 2) | (ch2 >> 4)
byte2 = ((ch2 & 0b00001111) << 4) | (ch3 >> 2)
byte3 = ((ch3 & 0b00000011) << 6) | ch4   ← 0 (padding)
```

---

#### Step 3. Visualization summary

```
Base64 input:        e_b1     e_b2     e_b3      =
6-bit groups:       [aaaaaa] [bbbbbb] [cccccc] [000000]
                    └───────┬────────┬────────┘
                            │        │
                 ┌──────────┘        │
                 ▼                   ▼
  Output bytes: [aaaaaa|bb] [bbbb|cccc]
                 byte1            byte2
                                   (byte3 ignored → padding)
```

Result:  
→ **2 decoded bytes**, 1 padding (`=`)  
→ **decoded length = expected − 1**

(with two `==` paddings):

This case means the **last group** encodes only **1 real byte** of data.  
`ch2`, `ch3`, and `ch4` either partially or entirely contain artificial bits due to padding.

---

#### Step 1. Base64 6-bit values (each from lookup)

Thanks to padding we know that only the first two bits of `ch2` are real;  
the remaining four of `ch2`, and the entirety of `ch3` and `ch4`, are padding.

```
ch1   ch2   ch3   ch4
[00aaaaaa][00bbbbbb][00000000][00000000]   ← ch3 = 0, ch4 = 0 because '=='
```

---

#### Step 2. Bit alignment and extraction into bytes

We know that we have only one real byte; the rest is artificial.

```
  byte1: aaaaaabb
  byte2: bb000000   ← all padded bits
  byte3: 00000000   ← all padded bits
```

So effectively:

```
byte1 = (ch1 << 2) | (ch2 >> 4)
byte2 = ((ch2 & 0b00001111) << 4) | (ch3 >> 2)   ← 0 (padding)
byte3 = ((ch3 & 0b00000011) << 6) | ch4          ← 0 (padding)
```

---

#### Step 3. Visualization summary

```
Base64 input:        e_b1     e_b2      =        =
6-bit groups:       [aaaaaa] [bbbbbb] [000000] [000000]
                    └───────┬────────┘
                            │
                            ▼
  Output bytes: [aaaaaa|bb]
                 byte1
                    (byte2 and byte3 ignored → padding)
```

Result:  
→ **1 decoded byte**, 2 paddings (`==`)  
→ **decoded length = expected − 2**

# 2. Challenge 2

There's no magic around this one. Just taking into account that XOR'ing is a bit per bit operation. If we have to XOR two arrays of the same length, we'll do it byte per byte. For this we have a very comfortable way of indexing by iterating over a range of the length and accessing both arrays at the same time:

```go
for i := range len(array1):
   unXoredByte := array1[i] ^ array2[i]
   unXored[i] = unXoredByte
```

# 3. Challenge 3

This exercise has a really vague narration... Here we have to do two big things:

1. Character frequency scoring.

Character frequency analysis is a heuristic that uses the statistical distribution of characters in a language to evaluate how “natural” a piece of text looks. It allows comparing candidate plaintexts, result of a decrypting process, to find the one most likely to be correct — especially useful when brute-forcing thousands of possibilities. For instance, English text tends to have many spaces and vowels, so a decipher that fits that profile will usually score higher.

We can implement this with a simple function and a map, specific to a natural language. We can use an LLM to craft a precise scoring table. The map indicates the score of a specific character. Then there's a function that takes a slice of bytes, iterates over each of them and cumulates the score, returning the final score.

2. A single byte XOR

A single byte XOR decypher simply consists in XOR'ing all the bytes in the XORed array with a single byte. We'll have to do this for every possible character (for an uint8, this is 256 characters). Easy then. If we combine this with the scoring function we can know which character yields the highest score and it will probably be the best solution to the decipher.

# 4. Challenge 4

This is the same as exercise 3 but with a tweak. We'll do the challenge 3 algorithm to each line. If we get a higher score, we'll keep that as the best and probable solution. Easy as that.

# 5. Challenge 5

No explanation needed.

# 6. Challenge 6

There is indeed an error prone coding tendency for this one.

## Hamming distance

In Go, we can't access bit level. We'll do bitwise operations. For the Hamming Distance between two bytes, we'll XOR them, which keep differing bits with a 1. With a population-count of 1 we can know the distance.

## Breaking a repeating-key XOR

Since we don't know the key length we have to start by bruteforcing it. The standard approach is to bruteforce it by comparing normalized Hamming distances between blocks of different sizes:

1. Choose a space of key sizes to bruteforce. Say $[0, 40]$
2. For each candidate size `k`:
   - Split the ciphertext into consecutive blocks of length `k`.
   - Take as many complete block pairs as possible.
   - Compute the Hamming distance for each pair, then normalize each distance by dividing by `k`.
   - Average those normalized distances to get a average-normalized-hd for `k`.
3. The key size with the lowest average normalized distance is probably the best candidate.
4. Transpose the ciphertext. The ciphertext is a collection of `x` vectors of length `k`. If we transpose them we'll end up with `k` vectors of length `x`. Each vector is composed by one byte from each of the original vectors, all XOR'ed by the same key byte. This means we converted the problem into a single byte key XORing.
5. Each transposed block is the result of a single-byte XOR key. Solve each block using a single-byte XOR cracker (as in Challenge 3).
6. Collect the single-byte keys in order to reconstruct the full repeating key.
7. Decrypt the ciphertext with the recovered key.

# 7. Challenge 7

To work with AES in Go we'll simply use the library aes: we'll create a new block cipher with

```go

aes.NewCipher(key)
```

and encrypt/decrypt each block with the cipher passing it the key.

# 8. Challenge 8

AES' ECB mode is stateless and deterministic. So if we encrypt an array which has repeated blocks we'll have a cipher with repeated blocks in the same index of the cipher. To detect ECB mode in a cipher text that we know used AES:

1. Divide the cipher text in blocks of aes.BlockSize (16) and store them in a slice
2. Get the length of that slice
3. Map the blocks with a set (a map with null values)
4. If map key length and slice length differ, it's probably ECB encrypted

# 9. Challenge 9

Here we simply implement the padding algorithm.

# 10. Challenge 10

CBC mode is the same as the AES code but we'll XOR the plaintext with the IV (if it's the first block) or the previous cipher block. To decrypt we'll decrypt with the block cipher object and unXOR with the previous ciphertext.

# 11. Challenge 11

An encryption oracle is an entity (in practice, anything) that will give us information of an encryption routine or ciphertext beyond its encrypted form. It gives us an advantage and possibility of decrypting. In this challenge we'll emulate an oracle to help us perform chosen plain text attack. We'll send a text with a chosen content and we'll use that to our advantage to gather information of an encryption system.

Oracle for challenge 11:

              +-------------------+
              |    Input Data     |
              +-------------------+
                        │
                        ▼
              +-------------------+
              |   Preprocessing   |
              +-------------------+
             ┌──────────┴──────────┐
             │                     │
             ▼                     ▼
    +-----------------+   +-----------------+
    │  Prepend        │   │   Append        │
    │  5-10 bytes     │   │   5-10 bytes    │
    +-----------------+   +-----------------+
             │                     │
             └──────────┬──────────┘
                        │
                        ▼
              +-------------------+
              │  Oracle Encryption│
              +-------------------+
             ┌──────────┴──────────┐
             │                     │
    +-----------------+   +-----------------+
    │  ECB Mode       │   │   CBC Mode      │
    │ • Random Key    │   │ • Random Key    │
    │                 │   │ • Random IV     │
    +-----------------+   +-----------------+
             │                     │
             └──────────┬──────────┘
                        │
                        ▼
              +-------------------+
              │   Output          │
              │  Ciphertext       │
              │   Without IV      │
              +-------------------+

For this we'll easily use ECB's vulnerability of determinism. We have to choose a minimum amount of identical bytes that will yield always two repeated cipher blocks that we can detect.

Worst case: 10 random bytes eat our identical sequence, so we'll at least need three blocks because the first one will be useless. We'll use three blocks then. We'll try to find duplicated cipher blocks in the encryption and that's how we'll determine which mode is being used.

# 12. Challenge 12

We'll be working with a more complex Oracle. We'll have a constant but random key ECB encryption Oracle. Each encryption it _appends_ the given string by the exercise, which is Base64 encoded. Our attack will consist in decrypting this unknown text. We'll use ECB biggest vulnerability again, its determinism, and our tool will be the chosen plaintext attack, the only thing we have control of.

We could bruteforce block by block, checking if we made a duplicate one, with a chosen plaintext attack, but that's impossible and same as bruteforcing the key.

Instead we can send chosen 15 bytes and have the unknown text put a byte in the end of the block. We would know its cipher equivalent. We can now reproduce this exact same block except the last byte which we'll have to bruteforce with a space of 256 possible characters 0 -> 255. We can keep doing this, one byte at a time.

When we finish the first block, we'll have to move one block to the right our study window. We'll again start with a 15 bytes known block, except this time the block we send won't be the one storing the unknown byte, it will be the following one. We then have to use the first decrypted block as the to bruteforce the byte. And this until full decryption.

# 13. Challenge 13

ECB cut-and-paste is a chosen-plaintext attack against ECB. We'll craft a ciphertext and paste it in a convenient place to inject malicious text. We have two oracle functions:

- `Encrypt(profileFor(email))` — builds a profile string, escapes `=` and `&` (escaping is replacing reserved characters with an allowed one), then encrypts with **ECB** under a **constant but unknown key**.
- `Decrypt(cipher)` — available to us for verification.

The profile format produced by the server is:

```go
email=foo@bar.com
```

Because `=` and `&` are escaped, we cannot directly inject `role=admin`. Our only tool is **chosen plaintext** — we can feed arbitrary emails and get back the corresponding ciphertext blocks.

We can produce a valid ciphertext that decrypts to a profile where `role=admin`. For this we'll inject enough bytes to move the role, `user`, to the last block alone, with the padding. Now we inject an email with `admin` and its artificial padding, that we can cut and paste to replace the last block with `user`.

## Idea (high level)

1. Inject an email long enough to push user to the edge, alone with padding
2. Make the substring `admin` with PKCS#7 padding appear exactly as the plaintext of **one ECB block** so we get its encrypted block from the oracle.
3. Replace the user at the edge with the encrypted `admin` block from step 2.
4. Decrypting the modified ciphertext yields `role=admin`.

First we'll input

```
email=foo@baaar.com&uid=10&role=user
```

which will yield the blocks

```
|email=foo@baaar.|com&uid=10&role=|userPADDING
```

Now we need to replace last block with a custom admin block. It's easy if we add padding to "admin" as a byte slice:

```go
adminblock = paddingkcs7("admin")
```

we make sure it's encrypted as a standalone block:

```
|email=FFFFFFFFFF|adminblock|[···]
```

Now we can substitute this adminblock cipher into our edge user block and we'll have resolved the exercise

# 14. Challenge 14 🥶

We get a random length string preppended in the Oracle. So, this is a more complex scenario than challenge 12.

Note that I overcomplicated this challenge, because of the lack of comprehension and redactation of whoever wrote these f\*cking challenges. Really, if you don't understand the challenge, it's not your fault, it's the incompetency for writing of the person who announced them. From what I later understood the author intended the Oracle to use a single random length for every encryption, but I initially interpreted it that the length was random each time, which changes the whole game. Don't worry, we'll learn even more.

This won't let us be comfortable because the offset will change on each encryption. But we can craft a strategy around this, exploiting again chosen plain-text attack.

If we don't add a duplicated block that we have the ability to detect, we'll never resolve the attack. We have to know where to index on each time we want to make an operation with the cipher text. That's it, we have to elaborate a strategy to always have a sentinel block that whispers us the index. To its right we know what we have: the target text to decipher.

The comprehensive algorithm is the following:

## Overview

- Discover the cipher block size by scoring candidate sizes for duplicate blocks in a bruteforce attack.
- Now that we have the blocksize, create a randomized two-block sentinel. Record its ciphertext block to later be able to detect block alignment despite a random prefix on each encryption. This will be the sentinel cipher block.
- Determine the unknown suffix length, the target text. We can ignore the random preppend since we have the sentinel and can isolate the target text. Simply inject the sentinel with incrementing byte sizes and detect the length change. That'll be a full block padding and can know its size. We've already done this in other challenges.
- Recover the unknown suffix one byte at a time by matching chosen-plaintext ciphertext blocks. Same as challenge 12.

---

## Step 0 — Key

- Produce a 16-byte key from a cryptographically secure RNG (one key per execution, it never changes!)

---

## Step 1 — Block size discovery (`bruteforceBlocksize`)

1. Encrypt a random text first. Will serve as a sample to produce an initial set of candidate sizes (e.g., all `i` in `[5..40]`, the interested space where we want to bruteforce, where ciphertext length % `i` == 0).
2. For each candidate `bs`, repeat many trials, as in a statistic study (though we could avoid this, see notes in the code):
   - Make a random block `B` of length `bs` and form `B||B` (two identical blocks), the sentinel dup.
   - Build a custom sequence of the sentinel dup to ensure it will 100% yield a duplicated block if blocksize is the correct one. This sequence was deduced on paper... it consists in first, a sentinel dup, and it gets appended a number of bs times, same-block-pairs, separated by a random offset of bs-1 bytes.
   - Encrypt the probe; if ciphertext splits into `bs`-sized blocks and contains duplicates, increment `bs`'s score.
3. Select the `bs` with the highest score.

---

## Sentinel setup (`getSentinelCipher`)

- Build a random block `S` of length `blockSize` and duplicate it (`S||S`).
- Repeatedly encrypt `S||S` until two adjacent ciphertext blocks are identical.
- Return the ciphertext value of the repeated block (use the second of the pair).  
  _This value marks when `S||S` happened to align on block boundaries despite a random prepend._
- We'll use this same sentinel block and its cipher to reliably detect it. This will lower to 0% the chances of the random preppend containing an interfering, duplicated sequence as long as this doesn't happen during the description of the sentinel itself.

---

## Step 2 — Discover target text length (`bruteforceTextLength`)

1. Start with n = 0 and keep appending to the sentinel while recording the text length that comes after it (always, when detecting it, if not, keep encrypting)
2. Stop when we detect a change in length. This means that the Oracle added a full block of padding
3. Length of the text will be: length of the encrypted text with the full block of padding minus blocksize (due to the padding) minus n

---

## Step 3 — Byte-by-byte recovery

The best way to understand the dynamic of this will be to read the code.

---

## Encryption oracle (behavior)

- Prepend a random prefix of random length in `[0..999]` (length chosen with `math/rand.Intn(1000)`, content from `crypto/rand`).
- Append a fixed, base64-decoded secret suffix (the target)
- Encrypt the concatenation using AES-ECB with the run's key and return the ciphertext.

## Notes & practical tips

- The random prefix introduces noise in sentinel detection. Yes, it's really possible, and I experienced it myself, that the random preppend will end up yielding duplicates in the long run if you encrypt thousands of times.
- The sentinel detection relies on the randomized prefix occasionally aligning `sentinelDup` exactly on block boundaries, and that's the only occasion we have control over the unknown text indexes.

# 15. Challenge 15

Here we simply implement the PKCS7 padding algorithm. Note that we did this earlier because we needed it, this challenge is quite random at the height of the set.

# 16. Challenge 16

CBC complicates injection attacks because we can't use a duplicated block sentinel, since they will encrypt to different ciphers. But we'll use CBC characteristics to our advantage. Since we know it encrypts each block with the previous one, we can modify the previous cipher text itself to work things out.

A 1-bit error in a block completely corrupts it and replicates the 1-bit error in the following one (remember that plaintext is being XOR'ed against the previous cipher!). We can then modify the previous ciphertext bit by bit (each byte to a map of 256 chars) to get any text we want from the next one! This is called bitflipping attack. Note that this attack is only useful for injection, not for decrypting itself CBC.

Situation: we have an Oracle that preppends and appends constant strings to our input to later encrypt with CBC under a constant key.

Diagram: input -> "comment1=cooking%20MCs;userdata=" + input + ";comment2=%20like%20a%20pound%20of%20bacon" -> encryption

CBC is non deterministic because of the random IV, there's no way to cut-and-paste attack. We have to modify cipher text itself to take advantage of the XOR'ing. We can send %admin%True% which will get encrypted and we can know which bytes indexes from the previous cipher block we need to change. Then we have a ciphertext and we can change the respective indexes that will be used for XOR'ing our input from the previous block, bruteforcing those three bytes until they reveal our target ;admin=true.

# 17. Challenge 17 🥶

Apparently this is the best known attack on real world cipher cryptography. CBC Padding Oracle attack. We'll have a function that does the following under the same key:

1. Get a string
2. Encrypt it with CBC mode and return it with the IV

We have another function that decrypts it internally and returns an error if the padding is corrupt. This second function emulates a server side encryption consumer as it's deployed in servers, such as a cookie consumer, which leaks crypto information by [incorrect padding exception] exposure. That's the leak.

It turns out that it's possible to decrypt the ciphertexts provided by the Oracle. The intuition here is that if padding is correct we know plaintext, so we already have a decryption there.

We receive a binary signal indicating whether padding is _correct_ or _incorrect_.  
Consider the simplest example with **three blocks**, where the padding value is `0x01`:

$$
[\texttt{VVVV} \;|\; \texttt{AAAA} \;|\; \texttt{BBBB} \;|\; \texttt{CCC1}]
$$

When padding is valid, we know the **last byte** of the third block (plaintext) decrypts to `0x01`.

During encryption, the last plaintext byte undergoes these transformations:

$$
p \;\xrightarrow[]{\oplus c}\; p \oplus c \;\xrightarrow[]{E}\; C_p
$$

If we flip bits in the **previous ciphertext block**, replacing $ c $ with $ c' $, then decryption proceeds as:

$$
C_p \;\longrightarrow\; p' = p \oplus (c \oplus c')
$$

With only the padding oracle signal, we brute-force $ c' $ until the padding becomes valid (i.e., ends with `0x01`).  
To ensure it's not a false signal (e.g, 22, 333, 4444, etc..., though highly improbable), we can later toggle $ c\_{-1} $ and retest.

We then have the simple relation:

$$
c' \oplus (p \oplus c) = 0x01
$$

and therefore:

$$
p = 0x01 \oplus c'
$$

A simple 1 incognito equation. That's it. Let's be more precise in the algorithm.

Definitions: $B_{n-1}$ = previous (control) block, $B_n$ = target block, $C_i$ = cipher byte, $o_{pd}$ = original padding value, $C_o$ = original corresponding cipher byte from previous block, $pd$ = padding value of interest.

1. Discover original padding size to know the bytes of interest.

2. For each target byte we create artificial paddings, of the value just enough so that the target byte would be the only needed to complete it  
   For a padding value $pd$ we want the last $pd-1$ plaintext bytes to equal $pd$.  
   For each byte we use the corresponding cipher byte in the previous block
   $$C_n = (o_{pd} \oplus C_o) \oplus pd$$
   To decipher block $B_n$ we use $B_{n-1}$ as the control block.

3. **Decrypting the last block:**  
   Start with artificial padding $o_{pd} + 1$.  
   Substitute the last $o_{pd+1} - 1 = o_{pd}$ corresponding previous-block cipher bytes with the equation above so those plaintext bytes become the desired $pd$.

4. Iterate over the studied byte: brute-force the cipher value that yields correct padding.

5. The recovered original plaintext byte is obtained by  
   $$p = (pd \oplus C_n) \oplus C_o.$$

6. Repeat steps 3 → 5 until the entire block is consumed.

7. **Decrypting non-last blocks:**

8. Remove the last decrypted blocks.

9. Start with artificial padding $1$ and repeat steps 3 → 5. Instead of using the original padding value, use the corresponding decrypted plaintext.  
   On finding padding $1$, ensure it is not a false positive caused by longer paddings (e.g. a pattern that would be padding $2,2$ or $3,3,3$, etc.) by changing the previous block's cipher byte and rechecking.
10. Decrypting the whole string is following this algorithm for every block of the ciphertext

# 18. Challenge 18

This CTR implementation is easy. We simply have to write a function that generates a keystream and, by indexing with floor division, we'll encrypt the stream byte by byte.

# 19. Challenge 19

We have a list of strings and we independently encrypt each one under the **same key** and **same nonce** with CTR.  
We end up with the same list encrypted — but crucially they **share the same keystream** bytes at each index.

**Vulnerability:** CTR with key+nonce reuse is a classic stream-cipher mistake.  
Since encryption is just a bytewise XOR of plaintext with keystream, ciphertexts at the same byte index share the same single-byte XOR:

$$
C_i^{(j)} = P_i^{(j)} \oplus K_i
$$

where $C_i^{(j)}$ is byte $i$ of ciphertext $j$, $P_i^{(j)}$ is the corresponding plaintext byte, and $K_i$ is the keystream byte for position $i$.

So for a fixed index $i$ across different ciphertexts:

$$
C_i^{(a)} \oplus C_i^{(b)} = P_i^{(a)} \oplus P_i^{(b)}
$$

This removes the keystream and gives the XOR of two plaintext bytes — we can see some hint of vulnerability.

**Attack idea:**

- Treat each byte position independently as a single byte XOR decrypt
- For byte position $i$, brute-force all 256 possible values of $K_i$
- Score the candidate by character frequency
- Pick the $k$ producing the highest score
- Repeat for all positions to recover the keystream — then unXOR all ciphertexts.

**Important caveat:**  
We can **recover** the keystream bytes by analysis and brute force, but we **cannot predict** the keystream from first principles without the key. The keystream equals AES(key, counter-block); without the key we cannot compute it — we only **recover** it because multiple ciphertexts leak structure when the keystream is reused. So, when truncating the texts list to the shortest one, that's our limit to decrypt, those longer we can't decrypt. Other positions can't be solved

# 20. Challenge 20

This is the same as challenge 19 but with other files. Remember: if two ciphertexts share something in the schema key <-> encrypt, they're vulnerable. In this case they share the same underlying keystream with which they were XOR'ed and that makes them vulnerable to a repeating key XOR attack.

# 21. Challenge 21 (mt19937)

Here it's just an implementation of the mt19937 algorithm. We can check our implementation's validity by generating the same sequence of, say, 20 values for a seed and comparing it with a standard implementation. They should yield the same sequence!

# 22. Challenge 22

Now we'll crack the seed of the MT19937. Why is this of interest? With the seed we'll be able to reproduce the whole sequence that the generator will be using forever and predict what values it will yield. It will no longer even be pseudo random.

The scenario for this challenge is the most simple one. We'll know when the PRNG gets initialized and we'll know that we have its first value. Also, we know that the seed is a unix timestamp and have a finite space for bruteforcing.

seed --population--> initialization vector --twist--> first state first number --tamper--> rand

Since the timestamp can occur only in a limited range we'll just bruteforce it.

# 23. Challenge 23

The concept behind the attack is really simple. MT19937 has an internal state and changes, but deterministically. Therefore, if the state is ever known, the PRNG itself can be replicated identically, no need even for seed.

We can know the state from the output because the tempering process is invertible. It has a property called involution $f(f(x)) = x$. If we have an output, we invert it and we have the exact value from the state. If we have 624 values, each from the same state, we can then duplicate the PRNG.

This attack works easy because we know the index of the PRNG. Otherwise, we could bruteforce as well but we'd need to guess the index as well.

How would we modify the PRNG to make this attack harder? Remember, the state has to undergo these transformations natively, so the answer relies in the tampering. We would have to tamper in a non invertible way. For that we would have to use a cryptographic hash.

# 24. Challenge 24

Again, the people writing these challenges have serious incapacities for writing. The challenge is the following: we'll create a stream cipher from MT19937.

The concept is simple. Instead of manually crafting a counter block (which is a known, predictable sequence of numbers) with a specific structure and incremental nature, we'll just use a raw PRNG to generate a keystream. Furthermore, we won't encrypt it. Very unsafe.

If the seed space is small (say, 16 bits, such as this challenge), it can be bruteforced, which are the intentions of the authors for this challenge. We'll do this: we'll inject a known plaintext and get an encryption. We know the indexing of our injection, so we'l unXOR that sequence of the encryption with the plaintext to recover the underlaying random numbers. We know these numbers and index, so now we can bruteforce the seed by comparing the generated values with the recovered ones.

We take some assumptions for this attack to work:

- we know the round of the PRNG
- we know the seed space of the PRNG
- we know the index of our plaintext injection

