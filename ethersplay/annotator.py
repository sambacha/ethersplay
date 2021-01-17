from binaryninja import log_error

# from constants import ADDR_SZ
from .common import ADDR_SIZE as ADDR_SZ


def get_annotation_for_stack_offset(function, address, offset=0):
    """offset is in terms of EVM stack slots"""

    sp = function.get_reg_value_at(address, "sp")
    # sp should be a offset
    if hasattr(sp, "offset"):
        spoff = sp.offset
    else:
        # binary ninja couldn't track the sp offset. bail out early
        return "<??? sp = " + str(sp) + ">"

    val = function.get_stack_contents_at(address, spoff + ADDR_SZ * offset, ADDR_SZ)
    if hasattr(val, "value"):
        if val.value > 2 ** 10:
            return hex(val.value)
        else:
            return str(val.value)
    else:
        return "<???>"


_ANNOTATIONS = {
    "CALLDATALOAD": ("input_offset",),
    "CALLDATACOPY": ("mem_offset", "input_offset", "len"),
    "CODECOPY": ("mem_offset", "code_offset", "len"),
    "EXTCODECOPY": ("addr", "mem_offset", "code_offset", "len"),
    "MSTORE": ("address", "value"),
    "SSTORE": ("address", "value"),
    "SLOAD": ("address",),
    "MLOAD": ("address",),
    "CREATE": ("value", "mem_offset", "mem_size"),
    "CALL": (
        "gas",
        "address",
        "value",
        "inp_offset",
        "inp_size",
        "ret_offset",
        "ret_size",
    ),
    "CALLCODE": (
        "gas",
        "address",
        "value",
        "inp_offset",
        "inp_size",
        "ret_offset",
        "ret_size",
    ),
    "DELEGATECALL": (
        "gas",
        "address",
        "inp_offset",
        "inp_size",
        "ret_offset",
        "ret_size",
    ),
    "STATICCALL": (
        "gas",
        "address",
        "inp_offset",
        "inp_size",
        "ret_offset",
        "ret_size",
    ),
    "RETURN": ("mem_offset", "mem_size"),
    "REVERT": ("mem_offset", "mem_size"),
    "SUICIDE": ("address",),
    "SHA3": ("offset", "size"),
    "ADD": ("op1", "op2"),
    "AND": ("op1", "op2"),
    "SIGNEXTEND": ("v",),
}


def is_dup(x):
    return x.upper().strip().startswith("DUP")


def dup2off(inststr):
    s = inststr.strip()[3:]
    o = int(s)
    return o - 1


def is_swap(x):
    return x.upper().strip().startswith("SWAP")


def swap2off(inststr):
    s = inststr.strip()[4:]
    o = int(s)
    return o


def annotate(view, function):
    if view.arch.name != "EVM":
        log_error(
            "This plugin works only for EVM bytecode (not for " + view.arch.name + ")"
        )
        return -1

    for inst, address in function.instructions:
        inststr = str(inst[0]).strip()
        comment = ""
        if inststr in _ANNOTATIONS:
            for stack_offset, annotation in enumerate(_ANNOTATIONS[inststr]):
                if annotation:
                    comment += ", {} = {}".format(
                        annotation,
                        get_annotation_for_stack_offset(
                            function, address, stack_offset
                        ),
                    )
        if is_dup(inststr):
            stack_offset = dup2off(inststr)
            comment = ", push {}".format(
                get_annotation_for_stack_offset(function, address, stack_offset)
            )
        if is_swap(inststr):
            stack_offset = swap2off(inststr)
            comment = ", swap(s[0] = {}, s[{}] = {})".format(
                get_annotation_for_stack_offset(function, address, 0),
                stack_offset,
                get_annotation_for_stack_offset(function, address, stack_offset),
            )
        if comment:
            # skip initial ', '
            comment = comment[2:]
            if len(comment) > 50:  # this number is pretty arbitrary
                comment = comment.replace(", ", ",\n")
            function.set_comment(address, comment)


def annotate_all(view):
    if view.arch.name != "EVM":
        log_error("This plugin works only for EVM bytecode")
        return -1

    for f in view.functions:
        annotate(view, f)
