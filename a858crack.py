#!/usr/bin/env python3
#The MIT License (MIT)
#
#Copyright (c) 2015 Isaac Dickinson
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.

# Designed to crack A858 posts, assuming they are hashes.

from multiprocessing import Value, Array, Process
import itertools

import hashlib

import string

import time

import ctypes
import sys

curr_hashes = Value("i", 0)
max_hashes = Value("d", 0)

results = Array(ctypes.c_char_p, 100) # 100 hash results should be enough

curr_offset = Value("i", 0)

def __crack_hashes(input_hash: str, hashtype: str, blocksize: int, unicode=False, binary=False):
    print("Running bruteforce crack on hash {} of type {} with {} character maximum blocksize...".format(input_hash, hashtype, blocksize))

    if unicode:
        chars = "".join([chr(x) for x in range(0, 109384)])
    elif binary:
        chars = "".join([chr(x) for x in range(0, 255)])
    else:
        chars = string.printable

    for block_size in range(0, blocksize):
        blocks = (''.join(i) for i in itertools.product(chars, repeat=int(block_size)))
        # Begin hashing.
        for block in blocks:
            h = hashlib.new(hashtype)
            try:
                h.update(block.encode())
            except UnicodeEncodeError:
                # Invalid unicode.
                continue
            if h.hexdigest() == input_hash:
                # Match!
                print("Collision found at hash {}".format(curr_hashes.value))
                results[curr_offset] = str(curr_hashes.value) + ":" + hashtype + ":" + block
                curr_offset.value += 1
            curr_hashes.value += 1


def crack(maxhash, hashtype, input_hash, output_file=sys.stdout, interval=1, blocksize=8,
          unicode=False, binary=False):
    start_time = time.time()
    max_hashes.value = maxhash
    p = Process(target=__crack_hashes, args=(input_hash, hashtype, blocksize, unicode, binary))
    p.start()
    while True:
        curr_time = time.time()
        elapsed = curr_time - start_time

        # Calculate hps
        hps = round(curr_hashes.value / elapsed, 0)

        # Check to see if the operation has completed or not
        if max_hashes.value <= curr_hashes.value or not p.is_alive():

            # Forcefully terminate the process.
            p.terminate()

            print("Completed bruteforcing. {} results.".format(curr_offset.value), file=output_file)
            print("Hashed {h} hashes out of {m} in {s} seconds."
                  .format(h=curr_hashes.value, m=max_hashes.value, s=elapsed), file=output_file)
            print("Maximum blocksize {bs}, hashing scheme {s}".format(s=hashtype, bs=blocksize), file=output_file)
            print("Average hashes per second of {}".format(hps), file=output_file)
            for value in results:
                if value is not None: print("Collision detected: {}".format(value))
            break

        hps_f = "{nhash}{unit}/s".format(nhash=get_appropriate_rounded_size(hps), unit=get_appropriate_rounded_unit(hps))
        print("Computed {n}/{m} ({p}%) hashes after {e} seconds, at {s}         "
            .format(n=curr_hashes.value, e=round(elapsed,2), s=hps_f,
                    m=max_hashes.value, p=round(curr_hashes.value/max_hashes.value * 100 if curr_hashes.value > 0 else 0, 2)), end='\r')
        time.sleep(float(interval))

def get_appropriate_rounded_unit(b):
    if 1024 < b < 1048576:
        return 'KH'
    elif 1048576 < b < 1073741824:
        return 'MH'
    elif b > 1073741824:
        return 'GH'
    else:
        return 'hash'

def get_appropriate_rounded_size(b):
    if 1024 < b < 1048576:
        return str(round(b / 1024))
    elif 1048576 < b < 1073741824:
        return str(round(b / 1024 / 1024))
    elif b > 1073741824:
        return str(round(b / 1024 / 1024 / 1024))
    else:
        return str(round(b, 2))

if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description='Attempts to crack A858 hashes.')
    parser.add_argument("hash", help="The hash to attempt to decode", nargs=1)
    parser.add_argument("-t", "--hashtype", help="The type of hash to attempt to decode.", default="md5")
    parser.add_argument("-f", "--file", help="The file to write results to.", nargs="?", default=sys.stdout)
    parser.add_argument("-i", "--interval", help="The difference in seconds to print out current status.", default=1, nargs="?")
    parser.add_argument("-m", "--max", help="The maximum number of hashes to perform. Do not change this without good reason.", nargs="?", default=1e+16)
    parser.add_argument("-b", "--blocksize", help="The number of blocks to calculate. By default, this is 8.", nargs="?", default=8)
    parser.add_argument("-u", "--unicode", help="Test unicode hashes. WARNING: This will probably take longer than the lifespan of the universe to complete on a CPU.",
                        action="store_true", default=False)
    parser.add_argument("--binary", help="Test binary hashes in ranges 0-255. This is overriden by the --unicode option.",
                        action="store_true", default=False)

    args = parser.parse_args()

    if args.file != sys.stdout:
        fobj = open(args.file, 'w')
    else:
        fobj = sys.stdout

    args.blocksize = int(args.blocksize)

    if args.unicode and args.max == 1e+16:
        args.max = 20494173395672605997800089770768881156096
    if args.binary and args.max == 1e+16:
        args.max = 255**(args.blocksize - 1)
    elif args.max == 1e+16:
        args.max = 100**args.blocksize

    crack(float(args.max), args.hashtype, args.hash[0], output_file=fobj,
          interval=args.interval, blocksize=int(args.blocksize), unicode=args.unicode, binary=args.binary)