# Cryptopals

The [Cryptopals Crypto Challenge](https://cryptopals.com/) is a set of problems designed to develop understanding related to weakness in real world systems and modern cryptographic solutions.

I wanted to work on these challenges to learn more about modern cryptography and also solve interesting puzzles/problems to keep myself engaged and sharp.

## Solutions

I have written the solutions in rust by preferred language to work with because of it's functional interfaces. I could have opted for [Elixir](https://elixir-lang.org/) also, but I have decided to give up on my polyglot tendencies and focus on bringing all the absorbed knowledge over the years into use of single programming language.

This crate contains solutions and utilities for the challenge. The codebase is organized into three main modules:
- `encoding` - Encoding/decoding utilities (hex, base64)
- `crypto` - Cryptographic operations (XOR, etc.)
- `analysis` - Cryptanalysis tools (frequency analysis, etc.)

| Set | Challenge | Status |
|:---:|:---------:|:------:|
| [Basics](https://cryptopals.com/sets/1) | [Convert hex to base64](https://cryptopals.com/sets/1/challenges/1) | ✅ |
| [Basics](https://cryptopals.com/sets/1) | [Fixed XOR](https://cryptopals.com/sets/1/challenges/2) | ✅ |
| [Basics](https://cryptopals.com/sets/1) | [Single-byte XOR cipher](https://cryptopals.com/sets/1/challenges/3) | ✅ |
| [Basics](https://cryptopals.com/sets/1) | [Detect single-character XOR](https://cryptopals.com/sets/1/challenges/1) | ✅ |
