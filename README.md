# Mirai / Hajime Function Helpers

Helper scripts and reverse-engineering notes for my CYBR 570 final project comparing Mirai and Hajime with Ghidra BSim.

The project tested whether Mirai and Hajime are code relatives or whether they are only similar because they targeted the same IoT device ecosystem. Mirai is a malicious DDoS botnet. Hajime is a vigilante-style IoT worm that spreads through similar weaknesses but uses a decentralized peer-to-peer design.

This repository contains only helper scripts and documentation. It does **not** contain malware samples, unpacked payloads, MalwareBazaar API keys, Ghidra projects, or BSim databases.

## Repository Contents

```text
CYBR570FinalProjectScripts/
├── README.md
└── mirai-hajime-function-helpers/
    ├── requirements.txt
    └── scripts/
        ├── find_groundtruth_similar.py
        ├── lzma_unpack.py
        └── wrap_elf.py
```

## Scripts

### `scripts/find_groundtruth_similar.py`

This script builds a cleaner Mirai cohort for BSim instead of using every sample tagged as Mirai.

What it does:

- Uses a known Mirai seed hash as ground truth.
- Queries MalwareBazaar for related samples.
- Uses metadata such as `telfhash`, `tlsh`, architecture, filename, file size, and signature.
- Downloads candidate samples from MalwareBazaar.
- Extracts MalwareBazaar AES zip files using the standard `infected` password.
- Runs `file` on each extracted binary.
- Keeps only samples matching the target architecture and format.
- Logs KEEP / Reject decisions.

Purpose in the project:

This helped avoid mixing unrelated Mirai-like IoT botnet variants. BSim gave better results once the comparison set was source-aligned instead of just broadly tagged as Mirai.

### `scripts/lzma_unpack.py`

This script unpacks the Hajime samples.

What it does:

- Recreates the custom LZMA-style decompression behavior used by the packed Hajime samples.
- Reads packed Hajime binaries.
- Finds and decodes the compressed payload.
- Writes recovered `_unpacked.bin` files.

Purpose in the project:

The packed Hajime samples did not expose useful code directly in Ghidra. This helper recovered the real payloads so they could be wrapped, imported, decompiled, and added to the BSim database.

### `scripts/wrap_elf.py`

This script wraps recovered Hajime payloads as ELF files.

What it does:

- Takes `_unpacked.bin` payloads from the Hajime unpacker.
- Creates `_unpacked.elf` files.
- Sets the expected MIPS entry point.
- Produces files that Ghidra can import and analyze normally.

Purpose in the project:

This step turned raw unpacked Hajime payloads into analyzable ELF files so Ghidra could decompile the code and generate BSim signatures.

## Replication Steps

These steps assume the scripts are in this repository, but the malware samples are stored outside the repository.

Example working layout:

```text
/mnt/c/Users/tmg10/Documents/
├── mirai-hajime-function-helpers/
│   ├── README.md
│   ├── requirements.txt
│   ├── scripts/
│   └── docs/
└── MalwareSamples/
    ├── Hajime1.elf
    ├── Hajime2.elf
    ├── Mirai1.elf
    └── ...
```

Do **not** place malware samples inside this GitHub repository.

### 1. Enter the helper repository

```bash
cd /mnt/c/Users/tmg10/Documents/mirai-hajime-function-helpers
```

### 2. Create and activate a Python virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install requirements

```bash
pip install -r requirements.txt
```

### 4. Set the MalwareBazaar API key

Do this in the terminal only. Do not commit the key to GitHub.

```bash
export MB_API_KEY="YOUR-API-KEY-HERE"
```

### 5. Build a Mirai ground-truth-aligned cohort

Run the Mirai sourcing helper from the malware sample workspace:

```bash
cd /mnt/c/Users/tmg10/Documents/MalwareSamples

python3 ../mirai-hajime-function-helpers/scripts/find_groundtruth_similar.py \
  --seed 0ea04179b34505024e111f254542d43f53765dc03f784e1efd10a88893e52662 \
  --out ./GroundTruthSimilar_0ea04179 \
  --want 15 \
  --limit 1000
```

Expected result:

- Candidate samples are downloaded.
- Each candidate is extracted.
- `file` is used to verify architecture and format.
- The script logs KEEP / Reject decisions.
- Kept samples are written to `GroundTruthSimilar_0ea04179`.

Check the output:

```bash
file ./GroundTruthSimilar_0ea04179/*.elf
```

### 6. Unpack Hajime samples

From the malware sample workspace:

```bash
cd /mnt/c/Users/tmg10/Documents/MalwareSamples

python3 ../mirai-hajime-function-helpers/scripts/lzma_unpack.py
```

Expected result:

```text
Hajime1_unpacked.bin
Hajime2_unpacked.bin
Hajime3_unpacked.bin
...
```

Some samples may fail to unpack cleanly. In my project, nine of ten Hajime samples unpacked successfully.

### 7. Wrap unpacked Hajime payloads as ELF files

```bash
python3 ../mirai-hajime-function-helpers/scripts/wrap_elf.py
```

Expected result:

```text
Hajime1_unpacked.elf
Hajime2_unpacked.elf
Hajime3_unpacked.elf
...
```

Verify the files:

```bash
file Hajime*.elf Hajime*_unpacked.elf
```

### 8. Import samples into Ghidra

Import the following into a Ghidra project:

- The not-stripped Mirai ground-truth sample.
- The filtered Mirai cohort from `GroundTruthSimilar_0ea04179`.
- The unpacked Hajime ELF files, such as `Hajime1_unpacked.elf`.

Run Auto Analyze on each imported program and save the project.

### 9. Create a BSim database

From the Ghidra support directory:

```bash
cd /path/to/ghidra/support

./bsim createdatabase file:/home/greentea/bsim_db/mirai_hajime medium_nosize
```

### 10. Generate BSim signatures

```bash
mkdir -p /home/greentea/bsim_sigs

./bsim generatesigs ghidra:/path/to/GhidraProject /home/greentea/bsim_sigs \
  --bsim file:/home/greentea/bsim_db/mirai_hajime
```

### 11. Commit BSim signatures

```bash
./bsim commitsigs file:/home/greentea/bsim_db/mirai_hajime /home/greentea/bsim_sigs
```

### 12. Connect to BSim in Ghidra

In the Ghidra GUI:

```text
BSim → Manage Servers
```

Add the local H2 database:

```text
file:/home/greentea/bsim_db/mirai_hajime
```

### 13. Query Mirai functions

Open the not-stripped Mirai ground-truth sample and search these functions with BSim:

```text
syn_attack
udpplain_attack
cleanup_old_processes
enqueue
```

For each function:

```text
Right-click inside function → BSim → Search Selected Functions
```

Record the similarity and confidence values.

### 14. Query Hajime functions

Open an unpacked Hajime sample and rename the important functions based on the analysis:

```text
FUN_004066d0 → hajime_protocol_event_loop
FUN_00405770 → hajime_peer_session_manager
FUN_004036fc → hajime_peer_table_update
```

Then query each with BSim:

```text
Right-click inside function → BSim → Search Selected Functions
```

Record the similarity and confidence values.

### 15. Interpret results

Expected high-level result:

- Mirai functions match strongly within the ground-truth-aligned Mirai cohort.
- Hajime functions match strongly within the unpacked Hajime cohort.
- Mirai and Hajime do not appear to be source-code sisters based on the functions analyzed.
- Hajime appears more like an evolutionary response to Mirai in the same IoT worm ecosystem than a fork of Mirai.

## Safety Notes

Do not upload or commit:

- `.elf` malware samples
- `_unpacked.bin` files
- `_unpacked.elf` files
- MalwareBazaar API keys
- Ghidra project files
- BSim database files
- Raw sample archives

This repository is only for helper scripts, documentation, and reproducibility notes.
