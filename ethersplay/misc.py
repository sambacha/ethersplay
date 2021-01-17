import os

from binaryninja import log_error, get_save_filename_input, log_info

from .common import ADDR_SIZE as ADDR_SZ


def dump_codecopy_data(bv, address):
    disas = bv.get_disassembly(address).strip()
    inst = disas.split(" ")[0]
    if not inst.startswith("CODECOPY"):
        log_error(
            "Instruction '{}' at address {} is not a CODECOPY inst".format(
                inst, address
            )
        )
        return None

    for function in bv.get_functions_containing(address):
        sp = function.get_reg_value_at(address, "sp")
        # sp should be a offset
        if hasattr(sp, "offset"):
            spoff = sp.offset
        else:
            log_error(
                "binary ninja couldn't track the sp offset. Can't reliably determine stack arguments."
            )
            continue

        # stack pointer offsets
        # mem_offset = 0
        code_offset_offset = 1
        len_offset = 2

        # retrieve actual values
        code_offset = function.get_stack_contents_at(
            address, spoff + ADDR_SZ * code_offset_offset, ADDR_SZ
        )
        length = function.get_stack_contents_at(
            address, spoff + ADDR_SZ * len_offset, ADDR_SZ
        )

        # check if the values
        if not hasattr(code_offset, "value"):
            log_error(
                "can't determine code_offset stack parameter ("
                + repr(code_offset)
                + ")"
            )
            continue
        if not hasattr(length, "value"):
            log_error("can't determine len stack parameter (" + repr(length) + ")")
            continue

        c, l = code_offset.value, length.value
        raw_data = bv.read(c, l)

        dir_name = os.path.dirname(bv.file.filename)
        base_name = os.path.basename(bv.file.filename)

        default_filename = "{}_codecopy_{}_{}.raw".format(base_name, c, l)

        selected_filename = get_save_filename_input(
            "Select Filename?", "raw", os.path.join(dir_name, default_filename)
        ).decode("utf-8")

        if not selected_filename:
            selected_filename = default_filename

        full_path = os.path.join(dir_name, selected_filename)
        log_info("writing contents to " + repr(full_path))
        with open(full_path, "wb") as f:
            f.write(raw_data)

        return full_path

    log_error("Couldn't find function to resolve stack slots!")
    return None
