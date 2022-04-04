# In-place optimal pebble P_k
# Copyright (C) 2014 Berry Schoenmakers
import hashlib


class HashChain(object):

    def __init__(self, seed, k):
        self.seed = seed
        self.y = hashlib.sha1(self.seed.encode()).hexdigest()
        self.k = k
        self.q = self.k
        self.pebbles = []

        self.round = (1 << self.k) #- 1
        self.step = 1
        self.stop = 1
        self.current = None

    def setup(self):
        # Generates hash chain
        # Stores pebbles in z
        for h in range(self.round, 1, -1):
            if h == 1 << self.q:
                self.pebbles.insert(0, self.y)
                self.q -= 1
            self.y = hashlib.sha1(self.y.encode()).hexdigest()

    def next(self):

        if self.round > self.stop:
            self.round = self.round - self.step
            self.current = self.pebbles[0]
            print("Position {} Hash {}".format(self.round, self.current))
        else:
            print("End of chain")
            return None

        c = self.round  # r
        i = 0
        while ~c & 1:
            self.pebbles[i] = self.pebbles[i + 1]
            i += 1
            c >>= 1

        i += 1
        c >>= 1
        m = i
        s = 0
        while c:
            l = i
            while ~c & 1:
                i += 1
                c >>= 1
            j = self.round & ((1 << i) - 1)
            p = i & 1 ^ j & 1
            h = p + j * (i - m) + (m + 3 - l) * (1 << l) - (1 << m) >> 1
            q = h.bit_length() - 1
            for _ in range(p + i + 1 - s >> 1):
                y = self.pebbles[q]
                if h == 1 << q:
                    q -= 1
                self.pebbles[q] = hashlib.sha1(y.encode()).hexdigest()
                h -= 1
            m = i
            s = m + 1
            while c & 1:
                i += 1
                c >>= 1
