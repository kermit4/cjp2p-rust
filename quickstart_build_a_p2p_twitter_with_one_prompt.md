# Build a fully P2P Web App in One Prompt

---

## 1. Get the source and examples

```bash
git clone https://github.com/kermit4/cjp2p-rust.git 
cd cjp2p-rust
git clone https://github.com/kermit4/LCDP_web_apps.git 
```

---

## 2. Install Rust and build

```bash
# Install Rust (skip if you already have it)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Build (takes a few minutes the first time)
make release
```

---

## 3. Run the node

```bash
./target/release/cjp2p
```

In another window

```
git clone https://github.com/kermit4/LCDP_web_apps.git 
rm LCDP_web_apps/chirp.html
```

---

## 4. Ask Claude to write the game

Paste the prompt below into Claude as-is. It will produce a single, self-contained HTML file you drop into `cjp2p/origin/`.

---

### The Prompt

```
based on src/main.rs and the .html files linked fcom LCDP_web_apps/index.html as examples make something like a twitter but p2p, in cjp2p/origin/


---

