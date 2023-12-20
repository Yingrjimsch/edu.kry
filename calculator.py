from js import console
from math import gcd, prod
from random import choice, seed, randint
import functools
from sympy import randprime

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
