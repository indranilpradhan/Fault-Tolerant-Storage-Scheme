from __future__ import division
from __future__ import print_function
from random import randint
from random import seed
from random import randint
import hashlib
import Crypto.Util.number
import sys
from Crypto import Random
import random
from numpy.polynomial.polynomial import Polynomial as Poly
import numpy.polynomial.polynomial as polynomial

import functools

_RINT = functools.partial(random.SystemRandom().randint, 0)


def convert_string_asciisum(m):
    asc = [ord(c) for c in m]
    return sum(asc)

def calculate_z(g,q):
    temp = randint(1,q-1)
    z = (g**temp)%q
    return z

def hash_function(x1,x2,g,z,q):
    hash_val = ((g**x1)%q * (z**x2)%q)%q
    return hash_val

def loop_exponent(exponent, nr, r, p):
    while(nr != 1):
        nr = (nr*r)%p
        exponent= exponent+1
    return exponent

def generating_x(g):
    x = randint(1,g-1)
    return x

def loop_gen(nr, exponent, r, p, g):
    exponent = loop_exponent(exponent, nr, r, p)
    if(exponent == p-1 and exponent != None):
        g.append(r)

def generator(p):
    g = []
    for i in range(1,p):
        r = i
        exponent = 1
        nr = r%p
        loop_gen(nr, exponent, r, p, g)
    return random.choice(g)

def choosing_p(n):
    q = Crypto.Util.number.getPrime(n, randfunc=Random.get_random_bytes)
    return q


def digital_signature(m,q,g,x,z):
    M = convert_string_asciisum(m)
    k = 13 #randint(1, q-1)
    r = (g**k)%q
    e = (hash_function(r,M, g,z,q))
    s = (k-(x*e))%(q-1)
    return s,e


def _eval_at(poly, x, prime):
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum

def make_random_shares(k, n, prime):
    if k > n:
        raise ValueError("Pool secret would be irrecoverable.")
    poly = [_RINT(prime - 1) for i in range(k)]
    points = [(i, _eval_at(poly, i, prime))
              for i in range(1, n + 1)]
    return poly[0], points

def _extended_gcd(a, b):
    x = 0
    last_x = 1
    y = 1
    last_y = 0
    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y

def _divmod(num, den, p):
    inv, _ = _extended_gcd(den, p)
    return num * inv

def _lagrange_interpolate(x, x_s, y_s, p):
    k = len(x_s)
    assert k == len(set(x_s)),"points must be distinct"
    def PI(vals):
        accum = 1
        for v in vals:
            accum *= v
        return accum
    nums = []  # avoid inexact division
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(PI(x - o for o in others))
        dens.append(PI(cur - o for o in others))
    den = PI(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p)
               for i in range(k)])
    return (_divmod(num, den, p) + p) % p

def recover_secret(points, prime):
    if len(points) < 2:
        raise ValueError("need at least two shares")
    print(*points)
    x_s, y_s = zip(*points)
    return _lagrange_interpolate(0, x_s, y_s, prime)

def receiver(n,k,sending_mesage,p,g,x,z):
    count = 0
    new_message = []
    for i in sending_mesage:
        s,e = digital_signature(str(i[0][1]),p,g,x,z)
        if(int(s) != int(i[1]) or int(e) != int(i[2])):
            count = count+1
            continue
        new_message.append(i[0])
    if(count > n-k):
        print("Unable to recover the data")
    else:
        print("The secret in receiver is ",recover_secret(new_message,p))

if __name__ == "__main__":
    S = 1234
    n = 6
    k = 3
    p = choosing_p(5)
    g = generator(p)
    z = calculate_z(g, p)
    x = generating_x(g)
    n = 6
    k = 3

    secret, points = make_random_shares(k,n,p)

    sending_mesage = []
    for i in points:
        temp = []
        sign, hash_ = digital_signature(str(i[1]),p,g,x,z)
        temp.append(i)
        print(type(i))
        temp.append(sign)
        temp.append(hash_)
        sending_mesage.append(temp)

    print('Secret in sender ',secret)

    receiver(n,k,sending_mesage,p,g,x,z)
