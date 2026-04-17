import random

def bb84_protocol(num_bits=200, eve=False):

    # -------- Alice prepares --------
    alice_bits = [random.randint(0,1) for _ in range(num_bits)]
    alice_bases = [random.choice(["Z","X"]) for _ in range(num_bits)]

    # -------- Bob chooses bases --------
    bob_bases = [random.choice(["Z","X"]) for _ in range(num_bits)]

    bob_results = []

    # -------- Transmission --------
    for i in range(num_bits):

        bit = alice_bits[i]
        base_a = alice_bases[i]

        # ----- Eve intercepts -----
        if eve:
            eve_base = random.choice(["Z","X"])
            if eve_base != base_a:
                bit = random.randint(0,1)

        # ----- Bob measures -----
        if bob_bases[i] == base_a:
            measured = bit
        else:
            measured = random.randint(0,1)

        bob_results.append(measured)

    # -------- Sifting --------
    sift_indices = [i for i in range(num_bits) if alice_bases[i] == bob_bases[i]]

    if len(sift_indices) == 0:
        return "0"*32, 0.0

    alice_sift = [alice_bits[i] for i in sift_indices]
    bob_sift   = [bob_results[i] for i in sift_indices]

    # -------- Add realistic channel noise (2–5%) --------
    noise_rate = random.uniform(0.02, 0.05)

    for i in range(len(bob_sift)):
        if random.random() < noise_rate:
            bob_sift[i] ^= 1

    # -------- QBER --------
    errors = sum(a != b for a,b in zip(alice_sift, bob_sift))
    qber = errors / len(alice_sift)

    # -------- Final Key --------
    final_key_bits = alice_sift[:128]

    key_string = "".join(str(b) for b in final_key_bits)

    return key_string, round(qber, 4)
