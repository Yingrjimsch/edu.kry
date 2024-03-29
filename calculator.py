from js import console
from math import gcd, prod, ceil, log2, sqrt, log, floor
from random import choice, seed, randint, SystemRandom
import functools
from sympy import randprime
import numpy as np

def execute():
    res = ""
    calcType = Element('calcType').value
    if calcType == "ggT":
        res = my_gcd(int(Element("number_one").value), int(Element("number_two").value))
    elif calcType == "rsabasic":
        res = rsa_basic(int(Element("n").value), int(Element("m").value), 
                        int(Element("c").value), int(Element("e").value), int(Element("d").value))
    elif calcType == "scg":
        res = subgroup_cyclic_group(int(Element("base").value), int(Element("group").value))
    elif calcType == "modPow":
        res = my_mod_pow(int(Element("base").value), int(Element("exponent").value), 
                         int(Element("modulus").value))[1]
    elif calcType == "cma":
        res = common_modulus_attack(int(Element("modulus").value), int(Element("public_key_1").value), 
                         int(Element("private_key_1").value), int(Element("public_key_2").value))
    elif calcType == "lea":
        rsa_modules = [int(i) for i in Element("rsa_modules").value.split(',')]
        chiff = [int(i) for i in Element("chiffrates").value.split(',')]
        res = low_exponent_attack(rsa_modules, chiff)
    elif calcType == "dbe":
        unencrypted_records = [int(i) for i in Element("unencrypted_records").value.split(',')]
        res = encrypt_decrypt_database(unencrypted_records)
    elif calcType == "top":
        res = create_table_of_primes(int(Element("max_value").value))[1]
    elif calcType == "ipp":
        res = my_is_probable_prime(int(Element("number").value), int(Element("number_of_fermat_tests").value), 
                                   create_table_of_primes(int(Element("table_of_primes").value))[0])[1]
    elif calcType == "fe":
        res = find_exp(int(Element("base").value), int(Element("r").value))[1]
    elif calcType == "ff":
        res = find_factor(int(Element("n").value), int(Element("b").value))[1]
    elif calcType == "psp":
        res = my_probable_safe_prime(int(Element("bit_length").value), int(Element("certainity").value), 
                                   create_table_of_primes(int(Element("table_of_primes").value))[0])[1]
    elif calcType == "eg":
        res = el_gamal(int(Element("bit_length").value), int(Element("plain_text").value))
    elif calcType == "sf":
        res = my_sqrt_floor(int(Element("number").value))[1]
    elif calcType == "pr":
        x = 1 if Element("x").value == "" else int(Element("x").value)
        a = 1 if Element("a").value == "" else int(Element("a").value)
        res = my_pollard_rho(int(Element("number").value), x, a)[1]
    elif calcType == "qnr":
        res = find_quadratic_nonresidue(int(Element("number").value))[1]
    elif calcType == "ms":
        res = my_mod_sqrt(int(Element("number").value), int(Element("modulus").value))[2]
    elif calcType == "ea":
        res = ellipt_add(int(Element("p_x").value), int(Element("p_y").value), int(Element("q_x").value), 
                         int(Element("q_y").value), int(Element("p").value), int(Element("a").value), int(Element("b").value))[1]
    elif calcType == "ffl":
        accuracy = 0.001 if Element("accuracy").value == "" else float(Element("accuracy").value)
        res = find_fermat_liers(int(Element("n").value), accuracy)
    elif calcType == "cmt":
        res = carmichael_test(int(Element("n").value))
    elif calcType == "ifl":
        numbers_to_test = [int(i) for i in Element("numbers_to_test").value.split(',')]
        res = is_fermat_lier(int(Element("n").value), numbers_to_test)
    elif calcType == "euler":
        res = euler(int(Element("n").value))
    elif calcType == "mle":
        res = mod_linear_equation(int(Element("a").value), int(Element("b").value), int(Element("p").value))[1]
    elif calcType == "prl":
        G1 = [int(i) for i in Element("g1").value.split(',')]
        G2 = [int(i) for i in Element("g2").value.split(',')]
        G3 = [int(i) for i in Element("g3").value.split(',')]
        res = pollard_rho_logarithm(int(Element("p").value), int(Element("g").value), int(Element("a").value), 
                                    G1, G2, G3)
    elif calcType == "bsgs":
        res = baby_step_giant_step(int(Element("g").value), int(Element("a").value), int(Element("p").value))
    elif calcType == "poec":
        res = points_on_elliptic_curve(int(Element("p").value), int(Element("a").value), int(Element("b").value))[1]
    elif calcType == "mtp":
        res = message_to_point(int(Element("m").value), int(Element("a").value), int(Element("b").value), int(Element("p").value), int(Element("bit").value))[1]
    elif calcType == "ptm":
        res = point_to_message(int(Element("x").value), int(Element("bit").value))[1]
    elif calcType == "em":
        res = ellipt_mul(int(Element("p_x").value), int(Element("p_y").value), int(Element("factor").value), int(Element("p").value), int(Element("a").value), int(Element("b").value))[1]
    elif calcType == "me":
        m = [int(i) for i in Element("m").value.split(',')]
        m = m if len(m) > 1 else m[0]
        P = False if Element("point").value == "" else [int(i) for i in Element("point").value.split(',')]
        res = message_encrypt(int(Element("p").value), int(Element("a").value), int(Element("b").value), int(Element("k_a").value), int(Element("k_b").value), m, P)[1]
    elif calcType == "md":
        B = [int(i) for i in Element("b_enc").value.split(',')]
        C = [int(i) for i in Element("c_enc").value.split(',')]
        res = message_decrypt(int(Element("p").value), int(Element("a").value), int(Element("b").value), int(Element("k_a").value), B, C)[1]
    elif calcType == "ege":
        m = [int(i) for i in Element("m").value.split(',')]
        m = m if len(m) > 1 else m[0]
        P = False if Element("point").value == "" else [int(i) for i in Element("point").value.split(',')]
        res = el_gamal_ellipt(int(Element("p").value), int(Element("a").value), int(Element("b").value), int(Element("k_a").value), int(Element("k_b").value), m, P)
    Element('result').write(res)

def my_gcd(number_one, number_two):
    solution = "--- ggT ---"
    solution += f"\nggT({number_one}, {number_two}) = {gcd(number_one, number_two)}"
    return solution

def rsa_basic(N, m=False, c=False, e=False, d=False):
    # N produkt zweier primzahlen
    # m ist die unverschlüsselte nachricht
    # c ist die verschlüsselte nachricht
    # e ist ein verschlüsselungsexponent
    # e * d = 1 (mod ϕ(N))
    # öffentlicher Schlüssel N, e
    phi_N = phi(N)[0]
    solution = "--- RSA Basic ---"
    solution += f"\nN = {N} = {'*'.join(map(str, factorize(N)))}"
    solution += f"\nphi(N) = {'*'.join(map(str, list(map(lambda x: x - 1, factorize(N)))))} = {phi_N}"
    encryption_exponents = phi(phi_N)
    solution += f"\nEs gibt phi({phi_N}) Verschlüsselungsexponenten: {encryption_exponents[0]} "
    if not e:
        e = choice(encryption_exponents[1])
        solution += f"\nRandom verschlüsselungsexponent wird gewählt: {e}"
    if not d:
        d = pow(e, -1, phi_N)
        solution += f"\nModulares inverses von e ist d: {e}^-1 mod ({phi_N}) = {d}"
    if d and e:
        solution += f"\nTeste e * d = 1 (mod {phi_N}) => {e} * {d} = {e * d % phi_N} (mod {phi_N})"
    if not c and not m:
        return "Nachricht und verschlüsselte Nachricht sind nicht angegeben!"
    if not c:
        c = pow(m, e, N)
    solution += f"\nVerschlüsselung der Nachricht m: c:= {m}^{e} = {c} (mod {N})"
    if not m:
        m = pow(c, d, N)
    solution += f"\nEntschlüsselung der Nachricht m = {c}^{d} = {m} (mod {N})"
    return solution

def phi(n):
    result = 1
    vals = []
    for i in range(2, n):
        if (gcd(i, n) == 1):
            vals.append(i)
            result+=1
    return result, vals

def factorize(number):
    factors = []
    divisor = 2

    while number > 1:
        while number % divisor == 0:
            factors.append(divisor)
            number //= divisor
        divisor += 1
    return factors

def subgroup_cyclic_group(base, group):
    # base: basis der Subgruppe
    # group: Z_group
    solution = "--- Subgruppe finden ---"
    subgroup = []
    for i in range(1, group):
        element = pow(base, i, group)
        subgroup.append(element)
        solution += f"\n{base}^{i} mod {group} = {element}"
        if element == 1:
            break
    solution += f"\n{subgroup} mit Ordnung {len(subgroup)}"
    return solution

def my_mod_pow(base, exponent, m):
    solution = f'Basis: {base}\tExponent: {exponent}\tModulus: {m}'
    result = 1
    exponent_length = exponent.bit_length()
    solution += f'\nBitlänge des Exponenten: {exponent_length}\nExponent binär: {bin(exponent)}'
    for i in range(exponent_length):
        if (exponent & (1 << i)) != 0:
            result = (result * base) % m
            solution += f'\nBit an stelle {i} ist 1 => ({result} * {base}) mod {m} = {result}'
        base = (base * base) % m
        solution += f'\nBasis quadrieren => ({base} * {base}) mod {m} = {base}'
    return result, solution

def common_modulus_attack(m, e1, d1, e2):
    # m: common modulus
    # e1: öffentlicher Schlüssel 1
    # d: privater Schlüssel 1
    # e2: öffentlicher Schlüssel 2
    solution = "--- Common Modulus Attack ---"
    v = e1 * d1 - 1
    solution += f"\nv = e1 * d1 - 1 = {e1} * {d1} - 1 = {v}"
    gcd_v_e2 = gcd(v, e2)
    if gcd_v_e2 == 1:
        solution += f"\nggT von {v} und {e2} ist {gcd_v_e2}."
        d2 = pow(e2, -1, v)
        solution += f"\nd2 = e2^-1 (mod v) = {d2}"
    else:
        solution += f"\nggT von {v} und {e2} ist {gcd_v_e2}."
        d2 = pow(e2, -1, int(v / gcd_v_e2))
        solution += f"\nd2 = e2^-1 (mod v/gcd(v, e2)) = {d2}"
    return solution

def low_exponent_attack(rsa_modules, chiff):
    if len(rsa_modules) != len(chiff): return "Die länge der Module und chiffraten muss gleich sein!"
    solution = "--- Low Exponent Attack ---"
    x = 0
    for index, module in enumerate(rsa_modules):
        Mi = prod(filter(lambda m: m != module, rsa_modules))
        solution += f"\nM_{index+1} = m_1 * ... * m_{len(rsa_modules)} ohne m{index+1} = {Mi}"
        ui = pow(Mi, -1, module)
        solution += f"\nu_{index+1} = M_{index+1}^-1 (mod m{index+1}) = {ui}"
        x += (chiff[index] * ui * Mi) % prod(rsa_modules)
    x = x % prod(rsa_modules)
    solution += f"\nx = c_1 * u_1 * M_1 + ... + c_{len(rsa_modules)} * u_{len(rsa_modules)} * M_{len(rsa_modules)} (mod m1 * ... * m_{len(rsa_modules)}) = {x}"
    result = pow(x, 1 / len(rsa_modules))
    if pow(round(result), 3) == x:
        result = round(result)
    elif pow(floor(result), 3) == x:
        result = floor(result)
    elif pow(ceil(result), 3) == x:
        result = ceil(result)
    solution += f"\nDie gesendete Nachricht ist x^(1/module_length) = {x}^(1/{len(rsa_modules)}) = {result})"
    return solution

#Input sind x Datensätze (zahlen)
def encrypt_decrypt_database(unencrypted_records):
    solution = '---- Datenbank verschluesselung ---'
    keys = []
    database_decrypted = 0
    # Print unencrypted records
    for i in range(len(unencrypted_records)):
        solution += f'\nDatensatz Nr. {i}: {unencrypted_records[i]}'
    solution += '\n'
    # create keys
    for i in range(len(unencrypted_records)):
        s = generate_prime(unencrypted_records[i].bit_length(), 10)
        solution += f'\nDatensatz Nr {i} Schluessel: {s}'
        keys.append(s)

    m = functools.reduce(lambda x, y: x * y, keys, 1)
    solution += f'\nAlle Schluessel zusammen sind: {m}'
    solution += '\n'

    # Encrypt Database
    for i in range(len(unencrypted_records)):
        Mi = m // keys[i]
        solution += f'\nM{i} = {m} / {keys[i]} = {Mi}'
        ui = pow(Mi, -1, keys[i])
        solution += f'\nu{i} = M{i}^(-1) mod {keys[i]} = {ui}'
        
        database_decrypted += unencrypted_records[i] * ui * Mi
        solution += f'\nGesamtverschluesselung nach {i + 1} Variablen: {database_decrypted}'
        solution += '\n'
    
    solution += '\n---- Datenbank entschluesselung ---'
    # Decrypt
    for i in range(len(unencrypted_records)):
        decrypted_record = database_decrypted % keys[i]
        solution += f'\nDatensatz Nr. {i} = {database_decrypted} mod {keys[i]} = {decrypted_record}'    
    return solution

def generate_prime(min_bit_length, max_bit_length):
    seed()
    additional_bit_length = randint(0, max_bit_length)
    return randprime(2**(min_bit_length + additional_bit_length), 2**(min_bit_length + additional_bit_length + 1))

def create_table_of_primes(max_value):
    solution = "--- Primzahlentabelle ---"
    solution += "\n0 und 1 werden automatisch entfernt"
    table_of_primes = []
    table_of_bool_primes = [True] * max_value

    # Iterate over max_value and filter out even and multiples of 3
    for i in range(2, max_value + 1):
        
        table_of_bool_primes[i - 2] = i == 2 or i == 3 or (i % 2 != 0 and i % 3 != 0)
        if not table_of_bool_primes[i - 2]:
            solution += f"\n{i} keine Primzahl (teilbar durch 2 oder 3)"

    # Find one prime and remove all multiples
    for i in range(2, max_value + 1):
        if table_of_bool_primes[i - 2]:
            solution += f"\n{i} ist Primzahl"
            table_of_primes.append(i)
            if i >= sqrt(max_value):
                continue
            for j in range(i * i, max_value + 1, i):
                if not table_of_bool_primes[j - 2]:
                    continue
                solution += f"\n{j} keine Primzahl (vielfaches von {i})"
                table_of_bool_primes[j - 2] = False
    solution += f"\nPrimzahlen: {(',').join(map(str, table_of_primes))}"
    return table_of_primes, solution

def my_is_probable_prime(number, t, table_of_primes=[]):
    solution = "--- Ist vielleicht eine Primzahl ---"
    # Edge cases: if negative or four (not prime), if smaller or equal 3 then prime
    solution += "\nEdge cases 1 ist keine Primzahl 2 & 3 sind Primzahlen"
    if number < 2 or number == 4:
        return False, solution
    if number < 4:
        return True, solution
    

    # Iterate t times and make Fermat test (check if a^(n-1) = 1 (mod n))
    # First check list of known primes
    for prime in table_of_primes:
        if number == prime:
            solution += f"\n{number} ist Primzahl da schon berechnet"
            return True, solution
        if number % prime == 0:
            solution += f"\n{number} ist keine Primzahl da vielfaches von schon berechneter Zahl {prime}"
            return False, solution

    random_source = SystemRandom()
    # Fermat test
    while t > 0:
        a = random_source.randint(2, number - 2)  # random integer in [2, self-2]
        test = pow(a, number - 1, number)
        solution += f"\nFermat Test für {a} ergibt {test}."
        if test != 1:
            solution += f"\nDa {a}^-1 != 1 (mod {number}) ist, ist {number} keine Primzahl"
            return False, solution
        t -= 1
    solution += f"\nNach {t} versuchen ist {number} eine Primzahl"
    return True, solution

def find_exp(base, r):
    solution = "--- Find exponent ---"
    solution += f"\nz^x <= r: {base}^x <= {r}"
    res = int(floor(log(r) / log(base)))
    solution += f"\nfloor(log({r}) / log({base})) = {res}"
    return res, solution

def find_factor(n, B):
    solution = "--- Find Factor ---"
    a = 2  # Anfangswert von a

    # Schritt 1: Berechne a^(B!) mod n für B = 2, 3, ..., B
    for j in range(2, B + 1):
        # Berechne die Potenz a^j mod n
        solution += f"\n\n{a}^{j} = {pow(a, j, n)} (mod {n})"
        a = pow(a, j, n)

        # Berechne den ggT(a-1, n)
        gcd_result = gcd(a - 1, n)
        solution += f"\nggT({a} - 1, {n})"
        solution += f"\nCheck if 1 < {gcd_result} < {n} => {1 < gcd_result < n}"
        # Wenn 1 < ggT(a-1, n) < n, dann haben wir einen nicht-trivialen Faktor gefunden
        if 1 < gcd_result < n:
            solution += f"\nFactor found: {gcd_result}"
            return gcd_result, solution
    solution += f"\nNo Factor found"
    # Wenn kein Faktor gefunden wurde, gib n zurück, um anzuzeigen, dass die Methode versagt hat
    return n, solution

def my_probable_safe_prime(bit_length, certainty, table_of_primes):
    solution = "-- Wahrscheinliche Sichere Primzahl ---"
    if bit_length < 2:
        raise ArithmeticError("bitLength < 2")

    safe_prime = 0
    q = 0
    # Main loop for generating the safe prime
    while True:
        # Generate a candidate q
        q = randint(2**(bit_length - 2), 2**(bit_length - 1) - 1)
        q |= 1  # Ensure q is odd
        solution += f"\n\nZufälliger Kandidat: {q}"

        # Check if q ≡ 5 (mod 6)
        solution += f"\nÜberprüfen ob {q} = 5 (mod 6) => {q % 6 != 5}"
        if q % 6 != 5:
            continue  # If not, try again
        
        # Pretests with small odd primes
        passed_small_prime_tests = all((q - 1) // 2 % small_prime != 0 for small_prime in table_of_primes)
        solution += f"\n{q} is {passed_small_prime_tests} in table of primes"
        if not passed_small_prime_tests or not my_is_probable_prime(q, certainty)[0]:
            continue  # If pretests fail or primality check fails, try again

        # Calculate p = 2q + 1
        safe_prime = 2 * q + 1
        solution += f"\nCalculate 2*{q} + 1 = {safe_prime}"

        # Check if p is prime
        if my_is_probable_prime(safe_prime, certainty)[0]:
            break
    return safe_prime, solution

def el_gamal(bit_length, plain_text):
    solution = "--- El Gamal ---"
    public_key, private_key, part_solution = generate_key_pair(bit_length)
    solution += f"\n{part_solution}"
    ciphered_text, part_solution = create_ciphered_text(public_key, plain_text)
    solution += f"\n\n{part_solution}"
    deciphered_text, part_solution = create_deciphered_text(ciphered_text, public_key, private_key)
    solution += f"\n\n{part_solution}"
    return solution

def generate_key_pair(bit_length_public_key):
    solution = "--- Erstelle Key Pair ---"
    p, _ = my_probable_safe_prime(bit_length_public_key, 10, [])
    solution += f"\nPrimzahl p ist: {p}"
    g, part_solution = find_generator(p)
    solution += f"\n{part_solution}"
    private_key_alice = pow(g, randint(1, p - 1), p)
    solution += f"\nPrivate Key: {g}^({p} - 1) = {private_key_alice} (mod {p})"
    A = pow(g, private_key_alice, p)
    solution += f"\nA: {g}^{private_key_alice} = {A} (mod {p})"
    public_key_alice = [p, g, A]
    solution += f"\nPublic Key: [{p}, {g}, {A}]"
    return public_key_alice, private_key_alice, solution

def find_generator(p):
    solution = "--- Finde Generator ---"
    solution += "\nGenerator g muss g^(n/2) != 1 (mod p) und g^(n/(p/2)) != 1 (mod p) sein."
    n = p - 1
    is_generator_valid = False
    g = 0
    while not is_generator_valid:
        g = randint(2, p - 2)
        solution += f"\n\nRandom generator {g}"
        q = p // 2
        is_generator_valid = pow(g, n // 2, p) != 1 and pow(g, n // q, p) != 1
        solution += f"\n{g}^{n // 2} = {pow(g, n // 2, p)} (mod {p})"
        solution += f"\n{g}^{n // q} = {pow(g, n // q, p)} (mod {p})"
        if is_generator_valid:
            solution += f"\nGenerator gefunden: {g}"
        else:
            solution += f"\nKein Valider Generator!"
    return g, solution

def create_ciphered_text(public_key_alice, plain_text):
    solution = "--- Erstelle Ciphered Text ---"
    rand = randint(1, public_key_alice[0] - 1)
    b = pow(public_key_alice[1], rand, public_key_alice[0])
    solution += f"\nb: {public_key_alice[1]}^{rand} = {b} (mod {public_key_alice[0]})"
    B = pow(public_key_alice[1], b, public_key_alice[0])
    solution += f"\nB: {public_key_alice[1]}^{b} = {B} (mod {public_key_alice[0]})"
    c = pow(public_key_alice[2], b, public_key_alice[0]) * plain_text % public_key_alice[0]
    solution += f"\nc: {public_key_alice[2]}^{b} * {plain_text} = {c} (mod {public_key_alice[0]})"
    ciphered_text = [B, c]
    solution += f"\nCiphered Text: [{B},{c}]"
    return ciphered_text, solution

def create_deciphered_text(ciphered_text, public_key_alice, private_key_alice):
    solution = "--- Erstelle Deciphered Text ---"
    
    deciphered_text = (ciphered_text[1] *
                            pow(ciphered_text[0],
                                public_key_alice[0] - 1 - private_key_alice,
                                public_key_alice[0])) % public_key_alice[0]
    solution += f"\n{ciphered_text[1]} * {ciphered_text[0]}^({public_key_alice[0]} - 1 - {private_key_alice}) = {deciphered_text} (mod {public_key_alice[0]})"
    return deciphered_text, solution

def my_sqrt_floor(num):
    solution = "--- sqrt Floor ---"
    history = set()
    x = 1 << (num.bit_length() // 2)
    solution += f"\n1. Annäherung x: sqrt({num} mithilfe von Bitshift 1 << ({num.bit_length() // 2}) = {x}"
    while True:
        next_x = (x ** 2 + num) // (2 * x)
        solution += f"\nNächste Annäherung x: {x}^2 + {num} / (2 * {x}) = {next_x}"
        if next_x == x or next_x in history:
            break
        history.add(x)
        x = next_x
    solution += f"\nfloor(sqrt({num})) = {x}"
    return x, solution

def my_pollard_rho(num, x=1, a=1):
    # Check if smaller or equal one or prime
    solution = "--- Pollard Rho ---"
    is_probable_prime = my_is_probable_prime(num, 10)[0]
    if num <= 1 or is_probable_prime:
        solution += f"\nThere is no factor because {num} is prime"
        return 1

    # Check if it's an even number
    if num % 2 == 0:
        solution += f"\nFactor is 2, {num} is even."
        return 2
    y = x
    d = 0

    while d <= 1 or d >= num:
        x_old = x
        x = (x**2 + a) % num
        solution += f"\n\nx = ({x_old}^2 + {a}) = {x} (mod {num})"
        y_old = y
        y = ((y**2 + a)**2 + a) % num
        solution += f"\ny = (({y_old}^2 + {a})^2 + {a}) = {y} (mod {num})"
        d = gcd(abs(x - y), num)
        solution += f"{d} = ggT(|{x} - {y}|, {num}) = {d}"
    solution += f"\n\nFactor 1: {d}, Factor 2: {num // d}"
    return d, solution

def my_mod_sqrt(n, p):
    solution = "--- Tonelli Algorithmus ---"
    euler_check = pow(n, (p - 1) // 2, p) == 1

    if not euler_check:
        solution += f"\nkein ergebnis für {n} (mod {p})"
        return -1, solution

    is_simple_tonelli = p % 4 == 3
    solution += f"\nPrüfe einfachen Tonelli {p} = 3 (mod 4) => {p} = {p%4} (mod 4)"
    if is_simple_tonelli:
        res = pow(n, (p + 1) // 4, p)
        res2 = (-res) % p
        solution += f"\nIst Fall 1.\nWurzel: {n}^((p+1) / 4) = +-{res} = {res} oder {res2} (mod {p})"
        return res, res2, solution
    else:
        solution += "\nIst Fall 2"
        h, part_solution= find_quadratic_nonresidue(p)
        solution += f"\n{part_solution}"
        exponent_one = (p - 1) // 2
        exponent_two = p - 1
        solution += f"\nInitial Exponenten: ({p} - 1) / 2 = {exponent_one} und p - 1 = {exponent_two}"

        while exponent_one % 2 == 0:
            exponent_one //= 2
            exponent_two //= 2
            solution += f"\n\nNeue Exponenten: {exponent_one}, {exponent_two}"
            if pow(n, exponent_one, p) * pow(h, exponent_two, p) % p == p - 1:
                exponent_two = (exponent_two + (p - 1) // 2) % (p - 1)
                solution += f"\nUpdate exponent 2 = {exponent_two}"

        res = pow(n, (exponent_one + 1) // 2, p) * pow(h, exponent_two // 2, p) % p
        res2 = (-res) % p
        solution += f"\n{n}^(({exponent_one} + 1) / 2) * {h}^({exponent_two} / 2) = +-{res} = {res} oder {res2} (mod {p})"
        return res, res2, solution

def find_quadratic_nonresidue(p):
    solution = "--- Finde Quadratisches Nichtresidual ---"
    candidate = 1
    while True:
        candidate = randint(2, p - 1)
        solution += f"\n\nZufälliger kandidat: {candidate}"
        c1 = pow(candidate, (p - 1) // 2, p)
        solution += f"\n{candidate}^(({p} - 1) / 2) == {c1} (mod {p}) ==> muss subtrahiert mit {p} = -1 sein."
        solution += f"\n{c1} - {p} = {c1 - p}"
        if c1 - p == -1:
            break
    solution += f"\nQuadratisches Nichtresidual: {candidate}"
    return candidate, solution

def ellipt_add(P_x, P_y, Q_x, Q_y, p, a, b):
    solution = "--- Ellipt Add ---"
    if P_x >= p or P_y >= p:
        solution += f"\nFall d) {P_x} oder {P_y} ist grösser oder gleich p (unendlich Ferner Punkt)\nResultat: Q({Q_x}, {Q_y})"
        return [Q_x, Q_y], solution
    elif Q_x >= p or Q_y >= p:
        solution += f"\n{Q_x} or {Q_y} ist grösser oder gleich p (unendlich Ferner Punkt)\nResultat: P({P_x}, {P_y})"
        return [P_x, P_y], solution
    elif P_x != Q_x and P_x < p:
        solution += f"\nFall a) x1 != x2"
        m = (Q_y - P_y) * pow((Q_x - P_x), -1, p) % p
        solution += f"\nm: ({Q_y} - {P_y}) / ({Q_x} - {P_x}) = {m} (mod {p})"
        x3 = (m**2 - P_x - Q_x) % p
        solution += f"\nx3: {m}^2 - {P_x} - {Q_x} = {x3} (mod {p})"
        y3 = (-m * (x3 - P_x) - P_y) % p
        solution += f"\ny3: -{m}({x3 - P_x}) - {P_y} = {y3} (mod {p})"
        solution += f"\nResultat: P + Q = ({x3}, {y3})"
        return [x3, y3], solution
    elif P_x == Q_x and P_y == Q_y and P_y != 0:
        solution += f"\nFall b) x1 == x2 und y1 == y2 != 0"
        m = (3 * (P_x**2) + a) * pow((2 * P_y), -1, p) % p
        solution += f"\nm: (3 * {P_x}^2 + {a}) / (2 * {P_y}) = {m} (mod {p})"
        x3 = (m**2 - 2 * P_x) % p
        solution += f"\nx3: {m}^2 - 2* {P_x} = {x3} (mod {p})"
        y3 = (-m * (x3 - P_x) - P_y) % p
        solution += f"\ny3: -{m}({x3 - P_x}) - {P_y} = {y3} (mod {p})"
        solution += f"\nResultat: P + Q = ({x3}, {y3})"
        return [x3, y3], solution
    elif P_x == Q_x and P_y == (-Q_y % p):
        solution += f"\nFall c) x1 == x2 und y1 == -y2"
        solution += f"\nP + Q = O (unendlich Ferner Punkt)"
        return [p, P_y], solution
    else:
        raise ValueError("Point does not lie on the curve!")
    
def find_fermat_liers(n, accuracy=0.01):
    # n: die zahl von welchen man die Fermatlügner berechnet haben werden will.
    solution = f"--- Fermat Lügner von {n} ---\na^(n-1) = 1 (mod n) und ggT(a, n) = 1"
    fermat_liers = []
    for a in range(1, n):
        candidate = pow(a, n - 1, n)
        solution += f"\n\na^(n-1) = {a}^{n - 1} = {candidate} (mod {n})"
        if candidate == 1:
            candidate_gcd = gcd(candidate, n)
            solution += f"\nggT(a, n) = ggT({a}, {n}) = {candidate_gcd} (mod {n})"
            if candidate_gcd == 1:
                solution += f"\nFermat Lügner gefunden!"
                fermat_liers.append(a)
    solution += f"\n\nEs gibt {len(fermat_liers)} Fermat Lügner FL({n}) = {','.join(map(str, fermat_liers))}"
    solution += f"\nIn FL({n}) gibt es {len(fermat_liers)}/{n - 1} = {(len(fermat_liers) / (n - 1)) * 100}% Fermat Lügner."
    solution += f"\nUm {(1-accuracy) * 100}% sicher zu sein müssen ln({accuracy})/ln({len(fermat_liers) / (n - 1)}) = {ceil(log2(accuracy) / log2(len(fermat_liers) / (n - 1)))} Ziehungen benötigt."
    return solution

def carmichael_test(n):
    solution = f"--- Carmichael Test ---"
    solution += f"\nZahl muss quadratfrei sein"
    solution += f"\nKriterium (p-1)|(n-1) für Primfaktoren p muss erfüllt sein."
    factors = factorize(n)
    solution += f"\nFaktoren von {n} sind {factors}"
    if len(factors) != len(set(factors)):
        solution += f"\n{n} ist nicht quadratfrei also keine Carmichael Zahl"
        return solution
    solution += f"\n{n} ist quadratfrei, prüfe Primfaktoren kriterium:"
    for factor in factors:
        is_divisor = (n-1) % (factor-1) == 0
        if is_divisor:
            solution += f"\n\n{factor-1} ist teiler von {n-1}"
        else:
            solution += f"\n{factor-1} ist kein teiler von {n-1}, Zahl ist also keine Carmichael Zahl."
            return solution
    solution += "\nist carmichael Zahl!"
    return solution

def is_fermat_lier(n, S):
    solution = f"--- Prüfe für jede Zahl aus {S} ob Fermat Lügner ---"
    for s in S:
        res = pow(s, n-1, n)
        if res == 1:
            solution += f"\n\n{s}^{n-1} = {res} (mod {n}) => ist FL"
            factors = factorize(n-1)
            r = factors.count(2)
            u = int((n-1) / 2**r)
            solution += f"\n{n-1} = 2^{r} * {u}"
            for k in range(r):
                res_miller_rabiot = pow(s, pow(2,k) * u, n)
                if res_miller_rabiot == 1 or res_miller_rabiot == (n-1):
                    solution += f"\n{s}^{pow(2,k) * u} = {res_miller_rabiot} (mod {n}) => ist Starker Lügner"
                    break
            if not (res_miller_rabiot == 1 or res_miller_rabiot == (n-1)):
                solution += f"\n{s}^{u} = {res_miller_rabiot} (mod {n}) => ist kein Starker Lügner"
        else:
            solution += f"\n\n{s}^{n-1} = {res} (mod {n}) => ist kein FL und kein SL"
    return solution

def euler(n):
    solution = f"--- Finde Quadratische Reste modulo {n} mit Euler ---"
    quadratic_residual = []
    exponent = int((n - 1) / 2)
    solution += f"Exponent ({n} - 1) / 2 = {exponent}"
    for a in range(1, n):
        res = pow(a, exponent, n)
        if res == 1:
            solution += f"\n\n{a}^{exponent} = {res} (mod {n}) => ist ein QR"
            quadratic_residual.append(a)
        else:
            solution += f"\n\n{a}^{exponent} = {res} (mod {n}) => ist ein QNR"
    solution += f"\n\nQuadratische Reste Modulo {n}: {(',').join(map(str, quadratic_residual))}"
    return solution

def mod_linear_equation(a, b, p):
    solution = f"--- Modulare Lineare Gleichung ---"
    solution += f"\n{a}x = {b} (mod {p})"
    d = gcd(a, b)
    if d == 1:
        res = (pow(a, -1, p) * b) % (p)
        solution += f"\nx = {a}^(-1) * {b} (mod {p})"
    elif d > 1:
        solution += f"\nDivision durch ggt({a}, {b}) = {d} gibt:"
        a = int(a / d)
        b = int(b / d)
        n = int((p) / d)
        z = pow(a, -1, n)
        solution += f"\nz = {a}^-1 = {z} (mod {n})"
        x = []
        for k in range(d):
            xi = (z * b + k * n) % (p)
            solution += f"\nx{k} = {z} * {b} + {k * n} (mod {p}) = {xi}"
            x.append(xi)
    return x, solution

def pollard_rho_logarithm(p, g, a, G1, G2, G3):
    solution = "--- Pollard Rho für Logarithmus ---"
    r = 0
    s = 0
    xi = 1
    store = np.array([[xi, r, s]])
    not_terminating = True
    while not_terminating:
        if xi in G1:
            solution += f"\nx = {xi}, r = {r}, s = {s}, G = G1"
            solution
            xi = (xi * a) % p
            r += 1
        elif xi in G2:
            solution += f"\nx = {xi}, r = {r}, s = {s}, G = G2"
            xi = pow(xi, 2, p)
            r *= 2
            s *= 2
        elif xi in G3:
            solution += f"\nx = {xi}, r = {r}, s = {s}, G = G3"
            xi = (xi * g) % p
            s += 1
        store = np.append(store, np.array([[xi, r, s]]), axis=0)
        not_terminating = len(store[:, 0]) == len(set(store[:, 0]))
    solution += f"\nx = {xi}, r = {r}, s = {s}"

    indices = np.where(store[:, 0] == store[:, 0][len(store) - 1])
    r1 = store[indices[0][0], 1]
    s1 = store[indices[0][0], 2]
    r2 = store[indices[0][1], 1]
    s2 = store[indices[0][1], 2]
    solution += f"\n\n{a}^{r1} * {g}^{s1} = {a}^{r2} * {g}^{s2} (mod {p})"
    r1 -= r2
    s2 -= s1
    solution += f"\n{a}^{r1} = {g}^{s1} (mod {p})"
    solution += f"\n(einsetzen: {g}^x = {a})"
    solution += f"\n{g}^{r1}x = {g}^{s2} (mod {p - 1})"

    x, mlg_solution = mod_linear_equation(r1, s2, p - 1)
    solution += f"\n\n{mlg_solution}"
    for xi in x:
        if pow(g, xi, p) == a:
            solution += f"\n\nTest:{g}^{xi} = {pow(g, xi, p)} (mod {p})"
            solution += f"\nLösung ist {xi}"
            return solution
        
def baby_step_giant_step(g, a, p):
    solution = "--- Baby step Giant step ---"
    m = ceil(sqrt(p))
    solution += f"\ng = {g}, a = {a}, n = {p}, m = ceil(sqrt({p})) = {m}"
    solution += f"\nBaby Step:"
    solution += f"\nBerechnung (j, g^j) (mod n) fuer j = 0,1,2...{m - 1}"
    baby_step = []
    for j in range(m):
        g_j = pow(g, j, p)
        solution += f"\n({j}, {g_j})"
        baby_step.append([j, g_j])
    h = pow(g, -m, p)
    solution += f"\n\nh = {g}^(-{m}) = {h} (mod {p})"

    solution += f"\n\nGiant Step:"
    solution += f"\nBerechnung (i, ah^i) (mod n) fuer i = 0,1,2,...{ceil(p/m)}"
    for i in range(ceil(p/m)):
        ah_i = a * pow(h, i, p) % p
        solution += f"\n({i}, {ah_i})"
        if ah_i in np.array(baby_step)[:, 1]:
            j = np.where(np.array(baby_step)[:, 1] == ah_i)[0][0]
            x = i * m + j
            solution += f"\nKollision gefunden! Übereinstimmung mit ({j}, {ah_i})"
            solution += f"\n\nLösung x = {i} * {m} + {j} = {x} (mod {p})"
            break
    return solution

def points_on_elliptic_curve(p, a, b):
    solution = f"--- Tabelle mit Punkten auf Elliptischer Kurve x^3 + {a}x + {b}"
    points = []
    for i in range(p):
        s_x = (i**3 + a*i + b)  % p
        solution += f"\n\nsx = {i}^3 + {a}*{i} + {b} = {s_x} (mod {p})"
        has_root = pow(s_x, int((p-1) / 2), p) == 1
        y = "-"
        if has_root:
            solution += f"\nHat wurzel: {a}^(({p}-1) / 2) = {pow(a, int((p-1) / 2), p) == 1} (mod {p})"
            p1, p2, part_solution = my_mod_sqrt(s_x, p)
            solution += f"\nWurzel mit tonelli gibt: {p1} oder {p2}"
            points.append([i, p1])
            points.append([i, p2])
        else:
            solution += f"\nHat keine Wurzel"
    solution += f"Menge der Punkte ist: {','.join([f'({p[0]},{p[1]})' for p in points])},O.\nAnzahl: {len(points) + 1}"
    return points, solution

def message_to_point(m, a, b, p, bit):
    solution = f"Nachricht {m} auf Punkt der Elliptischen Kurve x^3 + {a}x + {b} mit Bitshift von {bit} bringen."
    x = m << bit
    solution += f"\nLinksshift von {m} um {bit} = {x}"
    for _ in range(2**bit):
        
        s = (pow(x, 3, p) + a*x + b) % p
        solution += f"\n\nBerechne s = {x}^3 + {a}*{x} + {b} = {s} (mod {p})"
        y = my_mod_sqrt(s, p)[0]
        solution += f"\nFinde y mithilfe von Tonelli = {y}"
        if y != -1:
            break
        solution += f"\ny noch nicht gefunden, {x} um 1 erhöhen."
        x += 1
    solution += f"\ny = {y} gefunden."
    solution += f"\nPunkt auf Kurve ist: [{x}, {y}]"
    return [x, y], solution

def point_to_message(x, bit):
# x ist der erste wert des Punk M(x,y)
# bit ist die anzahl bit die zum verschieben verwendet wurden
# m return ist bitschift rückgängig und dann abgerundet
    m = floor(x/pow(2, bit))
    return m, f"m = floor({x}/{pow(2, bit)}) = {m}"

def ellipt_mul(P_x, P_y, factor, p, a, b):
    solution = f'--- Ellipt Multiply ----'
    result = [p, P_y]
    tmp = [P_x, P_y]
    factor_length = factor.bit_length()
    solution += f'\nBitlänge des Faktor: {factor_length}\nFaktor binär: {bin(factor)}'
    for i in range(factor_length):
        if (factor & (1 << i)) != 0:
            solution += f'\nBit an stelle {i} ist 1 => Ellipt Addieren: ({result[0]}, {result[1]}) + ({tmp[0]}, {tmp[1]})'
            result = ellipt_add(result[0], result[1], tmp[0], tmp[1], p, a, b)[0]
            solution += f"\n=({result[0]}, {result[1]}) "
        tmp = ellipt_add(tmp[0], tmp[1], tmp[0], tmp[1], p, a, b)[0]
    return result, solution

def message_encrypt(p, a, b, kA, kB, m, P=False):
    solution = "--- Encrypt Nachricht ---"
    if isinstance(m, int):
        m, part_solution = message_to_point(m, a, b, p, 4)
        solution += f"\n\n{part_solution}"
    if not P:
        res, part_solution = points_on_elliptic_curve(p, a, b)
        P = res[0]
        solution += f"\n\n{part_solution}"
    solution += "\nPunkt P auf Kurve ist {P}"
    A = ellipt_mul(P[0], P[1], kA, p, a, b)[0]
    solution += f"\n\nA = {kA} * {P} = {A} (mod {p})"
    B = ellipt_mul(P[0], P[1], kB, p, a, b)[0]
    solution += f"\n\nB = {kB} * {P} = {A} (mod {p})"
    kBA = ellipt_mul(A[0], A[1], kB, p, a, b)[0]
    C = ellipt_add(m[0], m[1], kBA[0], kBA[1], p, a, b)[0]
    solution += f"\n\nC = {m} + {kBA} = {C} (mod {p})"
    solution += f"\n\nEncrypted nachricht: [{B}, {C}]"
    return [B, C], solution

def message_decrypt(p, a, b, kA, B, C):
    solution = "--- Decrypt Nachricht ---"
    neg_kA_B = ellipt_mul(B[0], (-B[1]) % p, kA, p, a, b)[0]
    M = ellipt_add(neg_kA_B[0], neg_kA_B[1], C[0], C[1], p, a, b)[0]
    solution += f"\nBerechne Decryptete Message:"
    solution += f"\nM = -{kA} * {B} + {C} = {M} (mod {p})"
    return M, solution

def el_gamal_ellipt(p, a, b, kA, kB, m, P=False):
    solution = "--- El Gamal Ellipt ---"
    encrypted_message, part_solution = message_encrypt(p, a, b, kA, kB, m, P)
    solution += f"\n{part_solution}"
    decrypted_message, part_solution = message_decrypt(p, a, b, kA, encrypted_message[0], encrypted_message[1])
    solution += f"\n{part_solution}"
    if isinstance(m, int):
        _, part_solution = point_to_message(decrypted_message[0], 4)
        solution += f"\n{part_solution}"
    return solution
