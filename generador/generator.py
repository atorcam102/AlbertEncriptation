# safeprime_5000_print.py
import os, secrets, time
from concurrent.futures import ProcessPoolExecutor, as_completed

# ========= Config =========
BITS_P      = 3072         # tamaño de p (≈ 5000 bits)
MR_ROUNDS_Q = 16            # rondas MR para q
MR_ROUNDS_P = 16            # rondas MR para p
N_SMALL     = 5000          # cantidad de primos pequeños para precriba
WORKERS     = max(1, (os.cpu_count() or 8) - 1)  # procesos en paralelo
BATCH_SIZE  = 32            # candidatos por lote/proceso
LOG_EVERY   = 50            # log cada N lotes

OUT_P_FILE  = "safe_prime_5000_p.txt"
OUT_Q_FILE  = "safe_prime_5000_q.txt"

# ========= Utilidades =========
def sieve_primes(limit: int):
    """Primos <= limit (criba de Eratóstenes)."""
    bs = bytearray(b"\x01") * (limit + 1)
    bs[:2] = b"\x00\x00"
    p = 2
    while p * p <= limit:
        if bs[p]:
            step = p
            start = p * p
            bs[start:limit+1:step] = b"\x00" * ((limit - start)//step + 1)
        p += 1
    return [i for i, v in enumerate(bs) if v]

def first_n_primes(n: int):
    """Devuelve al menos n primos pequeños."""
    import math
    if n < 6:
        limit = 15
    else:
        nn = float(n)
        limit = int(nn * (math.log(nn) + math.log(math.log(nn)))) + 10
    arr = sieve_primes(limit)
    while len(arr) < n:
        limit *= 2
        arr = sieve_primes(limit)
    return arr[:n]

SMALL_PRIMES = first_n_primes(N_SMALL)

def miller_rabin(n: int, rounds: int) -> bool:
    """Miller–Rabin probabilístico (bases aleatorias)."""
    if n < 2:
        return False
    # cribado rápido
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n == p:
            return True
        if n % p == 0:
            return False

    # factoriza n-1 como d * 2^s
    d = n - 1
    s = (d & -d).bit_length() - 1
    d >>= s

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # 2..n-2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def pre_sieve(n: int) -> bool:
    """Descarta n si tiene divisor primo <= sqrt(n). Acepta n==p (primo pequeño)."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if p * p > n:
            break                 # no hay más divisores pequeños posibles
        if n % p == 0:
            return n == p         # True si n ES ese primo; False si es compuesto
    return True                    # pasa precriba; MR decidirá


def random_odd(bits: int) -> int:
    n = secrets.randbits(bits)
    n |= (1 << (bits - 1))  # bit alto
    n |= 1                  # impar
    return n

def candidate_q(bits_q: int) -> int:
    return random_odd(bits_q)

def is_probable_prime(n: int, rounds: int) -> bool:
    return pre_sieve(n) and miller_rabin(n, rounds)

# ========= Worker =========
def try_batch_q(args):
    """Prueba un lote de candidatos q y devuelve (p,q) si encuentra safe prime."""
    bits_p, mr_q, mr_p, batch = args
    bits_q = bits_p - 1
    for _ in range(batch):
        q = candidate_q(bits_q)
        if not is_probable_prime(q, mr_q):
            continue
        p = 2*q + 1
        if p.bit_length() != bits_p:
            continue
        if is_probable_prime(p, mr_p):
            return (p, q)
    return None

# ========= Orquestador =========
def generate_safe_prime_fast(bits_p=BITS_P, mr_q=MR_ROUNDS_Q, mr_p=MR_ROUNDS_P,
                             workers=WORKERS, batch_size=BATCH_SIZE):
    print(f"[Init] Safe prime ~{bits_p} bits | workers={workers}, batch={batch_size}, small_primes={len(SMALL_PRIMES)}")
    t0 = time.time()
    attempts = 0
    with ProcessPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(try_batch_q, (bits_p, mr_q, mr_p, batch_size)) for _ in range(workers)]
        while True:
            for fut in as_completed(futures):
                res = fut.result()
                attempts += batch_size
                if attempts % (LOG_EVERY * batch_size) == 0:
                    dt = time.time() - t0
                    print(f"[Log] Candidatos probados≈{attempts}  |  t={dt:.1f}s")
                if res is not None:
                    p, q = res
                    dt = time.time() - t0
                    print(f"[OK] Safe prime encontrado tras ≈{attempts} candidatos  |  {dt:.1f}s")
                    assert p == 2*q + 1
                    assert p.bit_length() == bits_p
                    return p, q, attempts, dt
                futures.remove(fut)
                futures.append(ex.submit(try_batch_q, (bits_p, mr_q, mr_p, batch_size)))

if __name__ == "__main__":
    t_start = time.time()
    p, q, attempts, elapsed = generate_safe_prime_fast()

    print("\n--- RESULTADOS ---")
    print("bits(p) =", p.bit_length(), "bits(q) =", q.bit_length())
    print("Verificando q...", "OK" if is_probable_prime(q, MR_ROUNDS_Q) else "FALLO")
    print("Verificando p...", "OK" if is_probable_prime(p, MR_ROUNDS_P) else "FALLO")

    # Imprime P y Q completos (¡son ~1500 dígitos cada uno!)
    print("\n=== SAFE PRIME P ===")
    print(p)
    print("\n=== Q = (P-1)//2 ===")
    print(q)

    # Guardar a archivos
    with open(OUT_P_FILE, "w") as f:
        f.write(str(p))
    with open(OUT_Q_FILE, "w") as f:
        f.write(str(q))

    print(f"\nGuardado en:\n  - {OUT_P_FILE}\n  - {OUT_Q_FILE}")
    print(f"Intentos aprox.: {attempts} | Tiempo total: {elapsed:.2f}s")
