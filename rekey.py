#!/usr/bin/env python3

import sys, os, secrets

MAGIC = bytes.fromhex("29d931f321c2dfe2d1459863bc8fd35bd0926386c07d02a85598b50abab058d8")
newkey = secrets.token_bytes(32)

def rekey(fname):
    with open(fname, "rb+") as f:
        f.seek(-64, os.SEEK_END)
        tr = f.read()
        if tr[32:] == MAGIC:
            print("key found, rotating")
            f.seek(-64, os.SEEK_END)
            f.write(newkey + MAGIC)
        else:
            print("no key found, adding")
            f.write(newkey + MAGIC)


if __name__=="__main__":
    for fn in sys.argv[1:]:
        rekey(fn)
    
