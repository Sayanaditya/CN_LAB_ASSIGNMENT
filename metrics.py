"""
metrics.py — Monte Carlo analysis of Checksum vs CRC-16 error detection.

Reimplements the same calc_checksum (RFC 1071) and calc_crc (poly 0x8005)
from frame.h, then runs thousands of random error injections to measure
detection rates across different error classes and bit-error counts.

Outputs:
    plots/detection_by_error_type.png
    plots/detection_vs_bit_flips.png
    plots/detection_vs_burst_length.png
    plots/false_accept_summary.png
"""

import os
import random
import struct
import matplotlib.pyplot as plt
import numpy as np

# ── Constants (matching frame.h) ─────────────────────────────────────────────

MAC_LEN      = 6
PAYLOAD_SIZE = 44
HEADER_SIZE  = MAC_LEN + MAC_LEN + 2 + 2   # 16 bytes
FCS_SIZE     = 4
DATA_LEN     = HEADER_SIZE + PAYLOAD_SIZE   # 60 bytes (what we compute over)

TRIALS = 10_000   # Monte Carlo iterations per test point

# ── Checksum & CRC (exact port of the C code) ───────────────────────────────

def calc_checksum(data: bytes) -> int:
    """16-bit Internet Checksum (RFC 1071)."""
    length = len(data)
    total = 0
    for i in range(0, length, 2):
        hi = data[i]
        lo = data[i + 1] if i + 1 < length else 0
        word = (hi << 8) + lo
        total += word
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def calc_crc(data: bytes) -> int:
    """CRC-16 with polynomial x^16 + x^15 + x^2 + 1 (0x8005)."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x8005) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

# ── Helper: build a random frame (as raw bytes, FCS zeroed) ─────────────────

def random_frame() -> bytearray:
    """Return DATA_LEN bytes of random frame data (header + payload)."""
    return bytearray(random.getrandbits(8) for _ in range(DATA_LEN))

# ── Error injection functions ────────────────────────────────────────────────

def flip_n_random_bits(data: bytearray, n: int) -> bytearray:
    """Flip exactly n distinct random bits in a copy of data."""
    corrupted = bytearray(data)
    total_bits = len(corrupted) * 8
    positions = random.sample(range(total_bits), min(n, total_bits))
    for pos in positions:
        byte_idx = pos // 8
        bit_idx  = pos % 8
        corrupted[byte_idx] ^= (1 << bit_idx)
    return corrupted


def inject_burst(data: bytearray, burst_len: int) -> bytearray:
    """Inject a burst error of given bit-length at a random position."""
    corrupted = bytearray(data)
    total_bits = len(corrupted) * 8
    if burst_len > total_bits:
        burst_len = total_bits
    start = random.randint(0, total_bits - burst_len)
    for i in range(burst_len):
        pos = start + i
        byte_idx = pos // 8
        bit_idx  = pos % 8
        corrupted[byte_idx] ^= (1 << bit_idx)
    return corrupted


def inject_word_swap(data: bytearray) -> bytearray:
    """Swap two random aligned 16-bit words (checksum-blind error)."""
    corrupted = bytearray(data)
    max_word = len(corrupted) // 2
    if max_word < 2:
        return corrupted
    a, b = random.sample(range(max_word), 2)
    # swap the two 16-bit words
    corrupted[2*a], corrupted[2*b] = corrupted[2*b], corrupted[2*a]
    corrupted[2*a+1], corrupted[2*b+1] = corrupted[2*b+1], corrupted[2*a+1]
    return corrupted


def inject_gx_multiple(data: bytearray) -> bytearray:
    """XOR with G(x) = 0xC0_02_80 at a random byte offset (CRC-blind error)."""
    corrupted = bytearray(data)
    idx = random.randint(0, len(corrupted) - 3)
    corrupted[idx]     ^= 0xC0
    corrupted[idx + 1] ^= 0x02
    corrupted[idx + 2] ^= 0x80
    return corrupted

# ── Detection test ───────────────────────────────────────────────────────────

def test_detection(original: bytearray, corrupted: bytearray):
    """Return (checksum_detected: bool, crc_detected: bool)."""
    orig_cs  = calc_checksum(bytes(original))
    orig_crc = calc_crc(bytes(original))
    corr_cs  = calc_checksum(bytes(corrupted))
    corr_crc = calc_crc(bytes(corrupted))
    return (corr_cs != orig_cs), (corr_crc != orig_crc)

# ── Experiment 1: Detection rate by error type ──────────────────────────────

def experiment_by_error_type():
    error_types = {
        "1-bit flip":       lambda d: flip_n_random_bits(d, 1),
        "2-bit flip":       lambda d: flip_n_random_bits(d, 2),
        "3-bit (odd)":      lambda d: flip_n_random_bits(d, 3),
        "8-bit burst":      lambda d: inject_burst(d, 8),
        "16-bit burst":     lambda d: inject_burst(d, 16),
        "Word swap\n(CS-blind)": lambda d: inject_word_swap(d),
        "G(x) inject\n(CRC-blind)": lambda d: inject_gx_multiple(d),
    }

    labels = list(error_types.keys())
    cs_rates  = []
    crc_rates = []

    for name, injector in error_types.items():
        cs_det = 0
        crc_det = 0
        for _ in range(TRIALS):
            orig = random_frame()
            corr = injector(orig)
            if orig == corr:     # skip if no actual change happened
                continue
            cs_ok, crc_ok = test_detection(orig, corr)
            cs_det  += cs_ok
            crc_det += crc_ok
        cs_rates.append(cs_det / TRIALS * 100)
        crc_rates.append(crc_det / TRIALS * 100)

    return labels, cs_rates, crc_rates

# ── Experiment 2: Detection rate vs number of random bit flips ───────────────

def experiment_vs_bit_flips():
    flip_counts = [1, 2, 3, 4, 5, 8, 12, 16, 24, 32, 48, 64]
    cs_rates  = []
    crc_rates = []

    for n in flip_counts:
        cs_det = 0
        crc_det = 0
        for _ in range(TRIALS):
            orig = random_frame()
            corr = flip_n_random_bits(orig, n)
            cs_ok, crc_ok = test_detection(orig, corr)
            cs_det  += cs_ok
            crc_det += crc_ok
        cs_rates.append(cs_det / TRIALS * 100)
        crc_rates.append(crc_det / TRIALS * 100)

    return flip_counts, cs_rates, crc_rates

# ── Experiment 3: Detection rate vs burst error length ───────────────────────

def experiment_vs_burst_length():
    burst_lengths = [1, 2, 4, 8, 12, 16, 20, 24, 32, 48, 64]
    cs_rates  = []
    crc_rates = []

    for blen in burst_lengths:
        cs_det = 0
        crc_det = 0
        for _ in range(TRIALS):
            orig = random_frame()
            corr = inject_burst(orig, blen)
            if orig == corr:
                continue
            cs_ok, crc_ok = test_detection(orig, corr)
            cs_det  += cs_ok
            crc_det += crc_ok
        cs_rates.append(cs_det / TRIALS * 100)
        crc_rates.append(crc_det / TRIALS * 100)

    return burst_lengths, cs_rates, crc_rates

# ── Plotting ─────────────────────────────────────────────────────────────────

COLORS = {
    "checksum": "#4A90D9",
    "crc":      "#E8585A",
}

def setup_style():
    plt.rcParams.update({
        "figure.facecolor": "#1A1A2E",
        "axes.facecolor":   "#16213E",
        "axes.edgecolor":   "#E0E0E0",
        "axes.labelcolor":  "#E0E0E0",
        "text.color":       "#E0E0E0",
        "xtick.color":      "#C0C0C0",
        "ytick.color":      "#C0C0C0",
        "grid.color":       "#2A2A4A",
        "grid.alpha":       0.6,
        "font.family":      "sans-serif",
        "font.size":        11,
    })


def plot_error_type(labels, cs_rates, crc_rates, path):
    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(labels))
    w = 0.35

    bars1 = ax.bar(x - w/2, cs_rates,  w, label="Checksum (RFC 1071)", color=COLORS["checksum"], edgecolor="#222", linewidth=0.5)
    bars2 = ax.bar(x + w/2, crc_rates, w, label="CRC-16 (0x8005)",     color=COLORS["crc"],      edgecolor="#222", linewidth=0.5)

    # value labels on bars
    for bar in bars1:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 0.8, f"{h:.1f}%", ha="center", va="bottom", fontsize=8, color="#B0B0D0")
    for bar in bars2:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 0.8, f"{h:.1f}%", ha="center", va="bottom", fontsize=8, color="#E0B0B0")

    ax.set_ylabel("Detection Rate (%)")
    ax.set_title("Detection Rate by Error Type  (10,000 trials each)", fontsize=14, fontweight="bold", pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0, 110)
    ax.legend(loc="lower right", framealpha=0.3)
    ax.grid(axis="y", linestyle="--")
    fig.tight_layout()
    fig.savefig(path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    print(f"  saved: {path}")


def plot_vs_bit_flips(flip_counts, cs_rates, crc_rates, path):
    fig, ax = plt.subplots(figsize=(10, 5.5))

    ax.plot(flip_counts, cs_rates,  "o-", color=COLORS["checksum"], linewidth=2, markersize=6, label="Checksum (RFC 1071)")
    ax.plot(flip_counts, crc_rates, "s-", color=COLORS["crc"],      linewidth=2, markersize=6, label="CRC-16 (0x8005)")

    ax.set_xlabel("Number of Random Bit Flips")
    ax.set_ylabel("Detection Rate (%)")
    ax.set_title("Detection Rate vs Number of Bit Flips  (10,000 trials each)", fontsize=13, fontweight="bold", pad=12)
    ax.set_ylim(90, 100.5)
    ax.legend(framealpha=0.3)
    ax.grid(True, linestyle="--")
    fig.tight_layout()
    fig.savefig(path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    print(f"  saved: {path}")


def plot_vs_burst_length(burst_lengths, cs_rates, crc_rates, path):
    fig, ax = plt.subplots(figsize=(10, 5.5))

    ax.plot(burst_lengths, cs_rates,  "o-", color=COLORS["checksum"], linewidth=2, markersize=6, label="Checksum (RFC 1071)")
    ax.plot(burst_lengths, crc_rates, "s-", color=COLORS["crc"],      linewidth=2, markersize=6, label="CRC-16 (0x8005)")

    ax.axvline(x=16, color="#FFD700", linestyle=":", linewidth=1.5, alpha=0.7, label="CRC-16 guaranteed limit (16 bits)")

    ax.set_xlabel("Burst Error Length (bits)")
    ax.set_ylabel("Detection Rate (%)")
    ax.set_title("Detection Rate vs Burst Error Length  (10,000 trials each)", fontsize=13, fontweight="bold", pad=12)
    ax.set_ylim(90, 100.5)
    ax.legend(framealpha=0.3)
    ax.grid(True, linestyle="--")
    fig.tight_layout()
    fig.savefig(path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    print(f"  saved: {path}")


def plot_false_accept_summary(labels, cs_rates, crc_rates, path):
    """Bar chart showing FALSE ACCEPT rates (= 100% - detection rate)."""
    cs_false  = [100 - r for r in cs_rates]
    crc_false = [100 - r for r in crc_rates]

    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(labels))
    w = 0.35

    bars1 = ax.bar(x - w/2, cs_false,  w, label="Checksum false-accept", color=COLORS["checksum"], edgecolor="#222", linewidth=0.5, alpha=0.85)
    bars2 = ax.bar(x + w/2, crc_false, w, label="CRC-16 false-accept",   color=COLORS["crc"],      edgecolor="#222", linewidth=0.5, alpha=0.85)

    for bar in bars1:
        h = bar.get_height()
        if h > 0.05:
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.15, f"{h:.2f}%", ha="center", va="bottom", fontsize=8, color="#B0B0D0")
    for bar in bars2:
        h = bar.get_height()
        if h > 0.05:
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.15, f"{h:.2f}%", ha="center", va="bottom", fontsize=8, color="#E0B0B0")

    ax.set_ylabel("False Accept Rate (%)")
    ax.set_title("False Accept Rate by Error Type  (lower is better)", fontsize=14, fontweight="bold", pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.legend(loc="upper right", framealpha=0.3)
    ax.grid(axis="y", linestyle="--")
    fig.tight_layout()
    fig.savefig(path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    print(f"  saved: {path}")

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    random.seed(42)
    setup_style()

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plots")
    os.makedirs(out_dir, exist_ok=True)

    print(f"Running Monte Carlo simulations ({TRIALS} trials each)...\n")

    # Experiment 1
    print("[1/3] Detection rate by error type...")
    labels, cs1, crc1 = experiment_by_error_type()
    plot_error_type(labels, cs1, crc1, os.path.join(out_dir, "detection_by_error_type.png"))
    plot_false_accept_summary(labels, cs1, crc1, os.path.join(out_dir, "false_accept_summary.png"))

    # Experiment 2
    print("[2/3] Detection rate vs bit flips...")
    flips, cs2, crc2 = experiment_vs_bit_flips()
    plot_vs_bit_flips(flips, cs2, crc2, os.path.join(out_dir, "detection_vs_bit_flips.png"))

    # Experiment 3
    print("[3/3] Detection rate vs burst length...")
    bursts, cs3, crc3 = experiment_vs_burst_length()
    plot_vs_burst_length(bursts, cs3, crc3, os.path.join(out_dir, "detection_vs_burst_length.png"))

    # Print summary table
    print("\n" + "=" * 70)
    print(f"{'Error Type':<22} {'Checksum Det%':>14} {'CRC-16 Det%':>14}")
    print("-" * 70)
    for lbl, cs, crc in zip(labels, cs1, crc1):
        clean_lbl = lbl.replace("\n", " ")
        print(f"{clean_lbl:<22} {cs:>13.2f}% {crc:>13.2f}%")
    print("=" * 70)
    print(f"\nAll plots saved to: {out_dir}")


if __name__ == "__main__":
    main()
