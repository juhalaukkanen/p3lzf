#!/usr/bin/env python

import argparse
import sys
import os
import struct
from binascii import hexlify, crc32

LZF_MAX_OFF = (1 << 13)

LZF_TYPE_1_HEADER_STRUCT = '<B B B BBBB'
LZF_TYPE_0_HEADER_STRUCT = '<B B B BB'

def hash_lzf(input_data):
    # NOTE: liblzf 3.6 uses own xor tech here
    return hash(input_data[:2])

def update_enc_lut(hash, input_offset, matches):
    if hash in matches:
        matches[hash] = matches[hash] + [input_offset]
    else:
        matches[hash] = [input_offset]

def get_matches(hash, matches):
    if hash in matches:
        return matches[hash]
    else:
        return []

def is_offset_within_bounds(offset, input_offset, block_size, block_offset):
    if offset == 0:
        return False
    if offset > input_offset:
        return False
    return offset >= block_offset

def lookup_match(input_data, input_offset, block_size, matches):
    LZF_MAX_REF = ((1 << 8) + (1 << 3))
    if (block_size - input_offset) < LZF_MAX_REF:
        block_ref_max = block_size - input_offset - 1
    else:
        block_ref_max = LZF_MAX_REF - 1

    if input_offset < LZF_MAX_OFF:
        block_offset = 0
    else:
        block_offset = input_offset - LZF_MAX_OFF

    offset_hash = hash_lzf(input_data[input_offset:])
    offsets = get_matches(offset_hash, matches)
    update_enc_lut(offset_hash, input_offset, matches)

    best_match_len = 0
    best_match_offset = 0
    for offset in offsets:
        if not is_offset_within_bounds(offset, input_offset, block_size, block_offset):
            continue # goes out of bounds - TODO: probably good to drop from dict?

        for candid_len in range(block_ref_max): # find out how long this match is
            if input_data[offset + candid_len] != input_data[input_offset + candid_len]:
                break

        if (input_offset + candid_len) >= block_size:
            continue # unfortunately too long

        # Update best match if it is longer than one found already
        if candid_len >= max(3, best_match_len): # required min 3 bytes shorter for encoding overhead (header)
            best_match_len = candid_len
            best_match_offset = offset

    #print("Size {} offset {}".format(best_match_len, best_match_offset))
    return best_match_len, best_match_offset

def start_lit_run(output_data, lit):
    output_data.append(lit)
    return output_data, 0

def end_lit_run(output_data, lit):
    backref_offset = -lit - 1
    output_data[len(output_data) + backref_offset] = (lit - 1) & 0xFF
    return output_data

def copy_lit_to_output(output_data, lit, input_data, input_offset):
    lit += 1
    output_data.append(input_data[input_offset])
    input_offset += 1

    LZF_MAX_LIT = (1 <<  5)
    if lit == LZF_MAX_LIT: # unlikely, restart run
        output_data = end_lit_run(output_data, lit)
        output_data, lit = start_lit_run(output_data, lit)

    return output_data, lit, input_offset

def end_run_with_undo_run_check(output_data, lit):
    output_data = end_lit_run(output_data, lit)
    if lit == 0:
        output_data.pop()

    return output_data

def handle_tail(output_data, lit, input_data, input_offset, block_size):
    if (len(output_data) + 3) > block_size: # at most 3 bytes can be missing here
        #print("Unlikely 3")
        return input_data, block_size, 0

    while (input_offset < block_size):
        output_data, lit, input_offset = copy_lit_to_output(output_data, lit, input_data, input_offset)
    output_data = end_run_with_undo_run_check(output_data, lit)

    return output_data, input_offset, len(output_data)

#
# compressed format
#
# 000LLLLL <L+1>    ; literal, L+1=1..33 octets
# LLLooooo oooooooo ; backref L+1=1..7 octets, o+1=1..4096 offset
# 111ooooo LLLLLLLL oooooooo ; backref L+8 octets, o+1=1..4096 offset
#
#
def lzf_compress(input_data, block_size):
    matches = dict()

    if block_size <= 0:
        return input_data, block_size, 0

    # pre set lit run to start
    lit = 1
    input_offset = 1
    output_data = bytearray([0, input_data[0]])

    while input_offset < (block_size - 2):
        lit_len, offset = lookup_match(input_data, input_offset, block_size, matches)

        if lit_len != 0:
            length = lit_len
            offset = input_offset - offset - 1 # change offset relative to input data

            output_data = end_run_with_undo_run_check(output_data, lit)

            # encode offset and length to output
            length -= 2 # len is now octets - 1
            input_offset += 1
            if (length < 7):
                output_data.append((offset >> 8) + (length << 5))
                #print("Did append {}".format((offset >> 8) + (length << 5)))
            else:
                output_data.append((offset >> 8) + (7 << 5))
                output_data.append(length - 7)
                #print("Did append {} and {}".format((offset >> 8) + (7 << 5), length - 7))
            output_data.append(offset & 0xFF)

            output_data, lit = start_lit_run(output_data, lit)

            length += 1
            if (input_offset + length) >= (block_size - 2):
                # Ran too long, unable to encode, abort.
                input_offset += length
                break

            while length > 0:
                # Update match for the whole length to the tables.
                update_enc_lut(hash_lzf(input_data[input_offset:]),
                                        input_offset,
                                        matches)
                input_offset += 1
                length -= 1
        else:
            if len(output_data) >= block_size: # unlikely
                #print("Unlikely 2")
                return input_data, block_size, 0

            # one more literal byte we must copy
            output_data, lit, input_offset = copy_lit_to_output(output_data, lit, input_data, input_offset)

        #print("Input {} Output {}".format(hexlify(bytes(input_data[input_offset])), hexlify(bytes(output_data))))

    return handle_tail(output_data, lit, input_data, input_offset, block_size)


def write_block(output_filename, output_data, output_size, compressed_output_size):
    #print("WRITING {} cs and {} us".format(compressed_output_size, output_size))
    with open(output_filename, "ab") as output_file:
        if (compressed_output_size > 0):
            lzf_header = struct.pack(LZF_TYPE_1_HEADER_STRUCT, 0x5A, 0x56, 1,
                                                                compressed_output_size >> 8,
                                                                compressed_output_size & 0xff,
                                                                output_size >> 8,
                                                                output_size & 0xff)
        else:
            lzf_header = struct.pack(LZF_TYPE_0_HEADER_STRUCT, 0x5A, 0x56, 0,
                                                                output_size >> 8,
                                                                output_size & 0xff)
        output_file.write(lzf_header)
        output_file.write(output_data)


def collect_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("InputFileName", help="The input file.")
    parser.add_argument("-b", default='1024', type=int, dest='block_size')
    parser.add_argument("-f", default=False, action="store_true",
         dest='overwrite_destination', help='Overwrite output file (InputFileName + ".lzf").')
    args = parser.parse_args()

    BLOCK_SIZE_MIN = 1
    BLOCK_SIZE_MAX = 65535
    assert (args.block_size >= BLOCK_SIZE_MIN and args.block_size <= BLOCK_SIZE_MAX), "Invalid block size"

    return args

args = collect_arguments()

output_filename = args.InputFileName + ".lzf"
if os.path.exists(output_filename):
    if not args.overwrite_destination:
        print('The destination file "{}" exists - will not overwrite.'.format(output_filename))
        exit(1)
    else:
        os.remove(output_filename)

with open(args.InputFileName, "rb") as input_file:
    # TODO can the endless loop be eliminated?
    while True:
        input_data = input_file.read(args.block_size)
        if input_data is None or len(input_data) <= 0:
            break

        output_data, output_size, compressed_output_size = lzf_compress(input_data, len(input_data))
        write_block(output_filename, output_data, output_size, compressed_output_size)
