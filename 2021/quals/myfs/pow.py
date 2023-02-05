#!/usr/bin/env python3
import secrets
import hashlib
import subprocess

##
# https://github.com/balsn/proof-of-work/blob/master/nc_powser.py
##
class NcPowser:
    def __init__(self, difficulty=10, prefix_length=16): 
        self.difficulty = difficulty
        self.prefix_length = prefix_length

    def get_challenge(self):
        return secrets.token_urlsafe(self.prefix_length)[:self.prefix_length].replace('-', 'b').replace('_', 'a')

    def verify_hash(self, prefix, answer):
        h = hashlib.sha256()
        h.update((prefix + answer).encode())
        bits = ''.join(bin(i)[2:].zfill(8) for i in h.digest())
        return bits.startswith('0' * self.difficulty)

def main():
    powser = NcPowser()
    prefix = powser.get_challenge()
    print(f'''
sha256({prefix} + ???) == {'0'*powser.difficulty}({powser.difficulty})...
''')

    ans = input('POW answer: ')
    if not powser.verify_hash(prefix, ans):
        print('Not correct!')
        return

    print('Passed!')

    # you code here
    import os
    os.system('docker run -i --rm myfs_myfs')

if __name__ == '__main__':
    main()

