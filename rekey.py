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

def writekey(fname, key):
    with open(fname, "rb+") as f:
        f.seek(-64, os.SEEK_END)
        tr = f.read()
        if tr[32:] == MAGIC:
            f.seek(-64, os.SEEK_END)
            f.write(key + MAGIC)
        else:
            f.write(key + MAGIC)
            
            
def readkey(fname):
    with open(fname, "rb") as f:
        f.seek(-64, os.SEEK_END)
        tr = f.read()
        if tr[32:] == MAGIC:
            print(tr[:32].hex())
        else:
            print("no key found")
            
if __name__=="__main__":
        if sys.argv[1]=='rekey':
            for fn in sys.argv[2:]:
                rekey(fn)
        elif sys.argv[1]=='readkey':
            for fn in sys.argv[2:]:
                readkey(fn)
        elif sys.argv[1]=='writekey':
            key = bytes.fromhex(sys.stdin.read(64))
            for fn in sys.argv[2:]:
                writekey(fn, key)
        else:
            print('usage: ./rekey.py [rekey|readkey|writekey] file [file...]\nnormal use is to rekey all binaries to be used together at once')

        
        
    
