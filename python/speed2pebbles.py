import hashlib


class Speed2Pebbles(object):

    def __init__(self, k, seed):
        """
        Speed-2 pebbling reverse hash chain implementation.
        Berry Schoenmakers
        :param k: k-pebblers used in algorithm
                  2^k hash chain length
        :param seed: Random value to initiate the hash chain

        :param z: list of pebblers

        :param c: k-bit length counter maintaining
                the state of pebblers
        """
        self.k = k
        self.seed = seed
        self.z = []
        self.c = 0

        self.y = hashlib.sha1(self.seed.encode()).hexdigest()
        self.round = 1 << self.k
        self.current = None
        self.q = 0

    def setup(self):
        # Generate chain and place the k pebbles
        self.q = self.k

        for h in range(1 << self.k, 1, -1):
            if h == 1 << self.q:
                self.z.insert(0, self.y)
                self.q -= 1
            self.y = hashlib.sha1(self.y.encode()).hexdigest()

    def next(self):
        # Runs one round of the algorithm

        # pop_0(c) remove trailing 0-bits
        # pop_1(c) remove trailing 1-bits

        if self.round > 1:
            self.round -= 1
            self.current = self.z[0]
            print("Position {} Hash {}".format(self.round, self.current))

        self.c = self.round
        i = 0

        # Check for trailing 0 bit
        while ~self.c & 1:
            # If there are trailing 0 bits
            # Means there are redundant pebbles
            # Replace z(0, i] pebbles with z[1, i]
            self.z[i] = self.z[i + 1]
            i += 1
            self.c >>= 1  # c = c / 2

        i += 1
        self.c >>= 1  # c = c / 2
        self.q = i - 1

        while self.c:
            # Update current q pebble based on pebble i
            self.z[self.q] = hashlib.sha1(self.z[i].encode()).hexdigest()

            # If the current q pebbler is inactive
            if self.q != 0:
                # Update it with the next value in chain
                self.z[self.q] = hashlib.sha1(self.z[self.q].encode()).hexdigest()

            # If counter c has trailing 0s
            # Move to the next pebble that needs to run in the round
            while ~self.c & 1:
                i += 1
                self.c >>= 1

            # If counter c has trailing 1s, remove them
            while self.c & 1:
                # Search in counter c the next pebble that needs to run
                i += 1
                self.c >>= 1

            self.q = i
