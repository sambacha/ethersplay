import os
import json
import atexit

import binaryninja as bn
from binaryninja import log_error, log_warn, log_info, BackgroundTaskThread

log_debug = log_info

try:
    import requests

    _requests_available = True
except ImportError:
    _requests_available = False

LOOKUP_4BYTE_URL = "https://www.4byte.directory/api/v1/signatures/"
CACHE_4BYTE_PATH = os.path.expanduser("~/.4byte_cache")
CACHE_4BYTE_FILE = os.path.join(CACHE_4BYTE_PATH, "cache.json")

_4byte_cache = None


def load_4byte_cache():
    global _4byte_cache
    log_debug("Loading 4byte lookup cache from: " + str(CACHE_4BYTE_PATH))
    if os.path.exists(CACHE_4BYTE_FILE):
        with open(CACHE_4BYTE_FILE, "r") as f:
            _4byte_cache = json.load(f)
            log_debug("4byte cache load success!")
    else:
        _4byte_cache = {}
    log_debug("Cache contains {} entries".format(len(_4byte_cache)))


def save_4byte_cache():
    if _4byte_cache:
        if not os.path.exists(CACHE_4BYTE_PATH):
            os.makedirs(CACHE_4BYTE_PATH)
        with open(CACHE_4BYTE_FILE, "w") as f:
            json.dump(_4byte_cache, f)


def init_cache():
    if _4byte_cache is None:
        load_4byte_cache()
        log_debug(
            "atexit handler: Saving 4byte lookup cache in " + str(CACHE_4BYTE_PATH)
        )
        atexit.register(save_4byte_cache)


def lookup_hash(sig, use_cache=True):

    if use_cache:
        init_cache()
        global _4byte_cache

        # if sig in _4byte_cache and _4byte_cache[sig]:
        #     return _4byte_cache[sig]
        tsig = _4byte_cache.get(sig, [])
        if tsig:
            return tsig

    if not _requests_available:
        log_error("couldn't import requests for fetching from 4byte.directory")
        return []
    try:
        res = requests.get(LOOKUP_4BYTE_URL, params={"hex_signature": sig})
        rj = res.json()
        results = rj["results"]

        if len(results) >= 1:
            sig_collisions = [r["text_signature"] for r in results]
            _4byte_cache[sig] = sig_collisions
            return sig_collisions
        else:
            log_warn("4.byte directory didn't yield any results for '{}'".format(sig))
            return []
    except AssertionError:
        raise
    except Exception as e:
        log_error("4byte lookup failed, reason ({}): {}".format(type(e), e))
        return []

    return []


def format_comment(sigs):
    assert len(sigs) >= 1
    text_sig = sigs[0]
    comment = ""
    if len(sigs) > 1:
        comment = "signatures with colliding hash:\n" + "\n".join(sigs)
    return text_sig, comment


def rename_all_functions(bv):
    init_cache()

    for function in bv.functions:
        if function.name.startswith("0x"):
            log_info("performing 4byte lookup for '{}'".format(function.name))
            try:
                # sig = "0x" + function.name[1:].strip()
                sig = function.name
                sigs = lookup_hash(sig)
                if len(sigs) >= 1:
                    new_name, comment = format_comment(sigs)
                    function.name = new_name

                    # imm = int(sig, 16)
                    # hash_value = "#{:0=8x}".format(imm)
                    # reset_symbol(bv, imm, hash_value, new_name)
                    if function.comment:
                        function.comment += "\n------\n"
                    function.comment += comment
                log_info(
                    "found {} text sigs for hash {} renamed function to {}".format(
                        len(sigs), sig, function.name
                    )
                )
            except AssertionError:
                raise
            except Exception as e:
                log_error(
                    "4byte lookup failed for function '{}' reason ({}): {}".format(
                        function.name, type(e), e
                    )
                )

    save_4byte_cache()
    return 0


def lookup_one_inst(bv, address):
    """
    Given an address to a PUSH instruction, take the immediate value from the
    push instruction, mask it s.t. it's 4 byte, perform a lookup on
    4byte.directory
    """
    init_cache()

    disas = bv.get_disassembly(address).strip()
    try:
        inst = disas.split(" ")[0]
        if not inst.startswith("PUSH"):
            log_error(
                "Instruction '{}' at address {} is not a PUSH inst".format(
                    inst, address
                )
            )
            return -1
        if "#" not in disas:
            log_error("invalid PUSH immediate value")
            return -1

        imm = int("0x" + disas.strip().split("#")[-1], 16)
        log_info("EVM: 4byte lookup of hash: {}".format(imm))

        # we mask the top bytes
        imm = imm & 0xFFFFFFFF

        sig = "0x{:0=8x}".format(imm)
        # hash_value = "#{:0=8x}".format(imm)

        sigs = lookup_hash(sig)
        log_debug("found {} sigs: {}".format(len(sigs), sigs))
        if len(sigs) == 0:
            return 0

        method_name, comment = format_comment(sigs)

        # reset_symbol(bv, imm, hash_value, method_name)

        if not comment:
            comment = "4byte signature: " + method_name

        if comment:
            for func in bv.get_functions_containing(address):
                log_debug("in function {}".format(func))
                c = func.get_comment_at(address)
                if c:
                    log_debug("setting comment")
                    c = "{}\n---\n{}".format(c, comment)
                    func.set_comment_at(address, c)
                else:
                    func.set_comment_at(address, comment)

    except AssertionError:
        raise
    except Exception as e:
        log_error(
            "4byte lookup failed for inst {} at address '{}' reason ({}): {}".format(
                disas, address, type(e), e
            )
        )

    save_4byte_cache()
    return 0


def lookup_all_push4(view, function):
    for inst, address in function.instructions:
        inststr = str(inst[0]).strip()
        if inststr.upper().strip() == "PUSH4":
            lookup_one_inst(view, address)


def update_cache():
    """
    Perform lookup of all cached items, s.t., new signature collisions are
    added to the cache. This should happen rather rarely so, it makes sense to
    run this only manually sometimes.
    """
    init_cache()
    for sig in _4byte_cache.keys():
        lookup_hash(sig, use_cache=False)
    save_4byte_cache()


class CacheUpdateThread(BackgroundTaskThread):
    def run(self):
        log_debug("inside update thread: starting lookups")
        update_cache()


def update_cache_bn(bv):
    log_debug("running update thread")
    x = CacheUpdateThread()
    x.start()


if __name__ == "__main__":
    update_cache()
