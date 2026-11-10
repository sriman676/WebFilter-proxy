#!/usr/bin/env python3
"""Soundtrack for the brag video: 20 s, 120 BPM (beat 0.5 s), A minor, one beat grid from frame 0.
Music and effects are written together: effects use chord tones and sit under the groove. Stdlib only."""
import math
import random
import struct
import wave

SR = 48000
DUR = 20.0
N = int(SR * DUR)
BEAT = 0.5
random.seed(7)

L = [0.0] * N
R = [0.0] * N


def hz(midi):
    return 440.0 * 2 ** ((midi - 69) / 12)


def add(start, samples, gain=1.0, pan=0.0):
    """Mix a mono list at `start` seconds; equal-power pan in [-1, 1]."""
    i0 = int(start * SR)
    gl = math.cos((pan + 1) * math.pi / 4) * gain
    gr = math.sin((pan + 1) * math.pi / 4) * gain
    for k, s in enumerate(samples):
        i = i0 + k
        if 0 <= i < N:
            L[i] += s * gl
            R[i] += s * gr


def env(n, a, d):
    """Attack `a` s, exponential decay with time constant `d` s."""
    na = max(1, int(a * SR))
    return [(k / na if k < na else math.exp(-(k - na) / (d * SR))) for k in range(n)]


def lowpass(xs, cutoff):
    a = 1 - math.exp(-2 * math.pi * cutoff / SR)
    y, out = 0.0, []
    for x in xs:
        y += a * (x - y)
        out.append(y)
    return out


def noise(n):
    return [random.uniform(-1, 1) for _ in range(n)]


def kick(gain=1.0):
    n = int(0.32 * SR)
    out, ph = [], 0.0
    for k in range(n):
        t = k / SR
        f = 45 + 95 * math.exp(-t * 28)
        ph += 2 * math.pi * f / SR
        out.append(math.sin(ph) * math.exp(-t * 9) * gain)
    return out


def hat(gain=1.0):
    n = int(0.05 * SR)
    ns = noise(n)
    lp = lowpass(ns, 6000)
    return [(a - b) * math.exp(-k / (0.012 * SR)) * gain for k, (a, b) in enumerate(zip(ns, lp))]


def pluck(midi, dur=0.6, gain=1.0, bright=1.0):
    n = int(dur * SR)
    f = hz(midi)
    e = env(n, 0.004, dur / 4)
    return [e[k] * (math.sin(2 * math.pi * f * k / SR) + 0.3 * bright * math.sin(4 * math.pi * f * k / SR)) * gain for k in range(n)]


def pad_note(midi, dur, gain):
    n = int(dur * SR)
    f = hz(midi)
    out = []
    for k in range(n):
        t = k / SR
        a = min(1.0, t / 0.35, (dur - t) / 0.35)
        s = 0.0
        for det in (-0.12, 0.0, 0.13):  # gentle chorus
            ff = f * 2 ** (det / 12)
            s += math.sin(2 * math.pi * ff * t) + 0.25 * math.sin(4 * math.pi * ff * t)
        out.append(s * a * gain / 3)
    return lowpass(out, 2200)


def bass_note(midi, dur, gain):
    n = int(dur * SR)
    f = hz(midi)
    e = env(n, 0.005, 0.18)
    return [e[k] * (math.sin(2 * math.pi * f * k / SR) + 0.35 * math.sin(4 * math.pi * f * k / SR)) * gain for k in range(n)]


def riser(start, length, gain):
    n = int(length * SR)
    ns = lowpass(noise(n), 3000)
    add(start, [s * (k / n) ** 2 * gain for k, s in enumerate(ns)], 1.0, 0.0)


def thud(start):
    n = int(0.9 * SR)
    out, ph = [], 0.0
    for k in range(n):
        t = k / SR
        f = 30 + 42 * math.exp(-t * 10)
        ph += 2 * math.pi * f / SR
        out.append(math.sin(ph) * math.exp(-t * 3.2))
    add(start, out, 0.9)
    add(start, [s * math.exp(-k / (0.06 * SR)) for k, s in enumerate(lowpass(noise(int(0.3 * SR)), 900))], 0.35)


# Chords per 2 s bar: Am, F, C, G (A minor, i-VI-III-VII).
CHORDS = [[57, 60, 64], [53, 57, 60], [55, 60, 64], [55, 59, 62]]
ROOTS = [45, 41, 48, 43]

# Pad through the whole piece; quieter in the hook.
for bar in range(10):
    t0 = bar * 2.0
    g = 0.05 if t0 < 3.5 else 0.085
    for i, m in enumerate(CHORDS[bar % 4]):
        add(t0, pad_note(m, 2.05, g), 1.0, (-0.4, 0.0, 0.4)[i])

# Hook: typing ticks on 16ths, plucks for the OK lines, the BLOCKED hit, a riser into the reveal.
for k in range(1, 8):
    add(k * 0.125, [s * 0.5 for s in hat(0.35)], 1.0, 0.3 if k % 2 else -0.3)
add(1.0, pluck(76, 0.5, 0.16), 1.0, -0.2)
add(1.5, pluck(81, 0.5, 0.16), 1.0, 0.2)
thud(2.0)
add(2.0, pluck(45, 1.4, 0.22, 0.5), 1.0)
add(2.0, pluck(52, 1.4, 0.12, 0.5), 1.0)
riser(2.5, 1.0, 0.10)

# Groove 3.5-18.0: kick on beats, hats off-beat, bass on 8ths ducked by the kick.
t = 3.5
while t < 18.0 - 1e-9:
    add(t, kick(0.55), 1.0)
    add(t + 0.25, hat(0.14), 1.0, 0.25)
    bar = int(t // 2.0)
    for e8 in (0.0, 0.25):
        add(t + e8 + 0.06, bass_note(ROOTS[bar % 4], 0.22, 0.20 if e8 else 0.14), 1.0)
    t += BEAT

# Risers into the cuts; plucks on dashboard rows and proof cards (chord tones, ascending).
for c in (6.0, 10.0, 14.5, 18.0):
    riser(c - 0.5, 0.5, 0.06)
for i, m in enumerate([69, 72, 76, 72, 74]):
    add(11.0 + i * 0.5, pluck(m + 12, 0.35, 0.05), 1.0, (-0.3, 0.3)[i % 2])
for i, m in enumerate([67, 71, 74, 79]):
    add(15.0 + i * 0.5, pluck(m, 0.6, 0.12), 1.0, (-0.25, 0.25)[i % 2])

# Outro: final kick and an A minor chord ringing out.
add(18.0, kick(0.6), 1.0)
for i, m in enumerate([45, 57, 60, 64, 69]):
    add(18.0, pluck(m, 2.0, 0.10, 0.4), 1.0, (-0.3, -0.1, 0.0, 0.1, 0.3)[i])

# Master: gentle fade-out over the last second, soft clip, normalize to -1 dBFS.
for i in range(N):
    t = i / SR
    g = 1.0 if t < 19.0 else max(0.0, 20.0 - t)
    L[i] = math.tanh(L[i] * g * 1.1)
    R[i] = math.tanh(R[i] * g * 1.1)
peak = max(max(abs(x) for x in L), max(abs(x) for x in R)) or 1.0
scale = 0.89 / peak
with wave.open("music.wav", "wb") as w:
    w.setnchannels(2)
    w.setsampwidth(2)
    w.setframerate(SR)
    w.writeframes(b"".join(struct.pack("<hh", int(L[i] * scale * 32767), int(R[i] * scale * 32767)) for i in range(N)))
print("music.wav written", round(peak, 3))
