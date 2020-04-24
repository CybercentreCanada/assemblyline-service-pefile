#!/usr/bin/env python

# ./generate_LCID.py < LCID > LCID.py

import pprint
import sys


def generate_lcid(f):
    lcid = {}
    for line in f:
        tpl = line.split("|")
        if len(tpl) == 3:
            lcid[int(tpl[2])] = tpl[0]
    return lcid


if __name__ == '__main__':
    print("LCID = \\")
    pprint.pprint(generate_lcid(sys.stdin))

