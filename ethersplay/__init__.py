from binaryninja import PluginCommand, Architecture

from printSourceCode import function_source_code_start
from coverage import function_coverage_start
from print_stack import function_printStack_start
from stack_value_analysis import function_stack_value_analysis_start
from evm import EVM, EVMView
import annotator
import lookup4byte


def is_valid_evm(view, function=None):
    return view.arch == Architecture['EVM']


PluginCommand.register("EVM Source Code",
                       "EVM Source Code Printer.",
                       function_source_code_start,
                       is_valid=is_valid_evm)

PluginCommand.register("EVM Manticore Highlight",
                       "EVM Manticore Highlight",
                       function_coverage_start,
                       is_valid=is_valid_evm)

PluginCommand.register_for_function("EVM Stack Value Analysis",
                                    "Run value-set analysis on the function",
                                    function_stack_value_analysis_start,
                                    is_valid=is_valid_evm)

PluginCommand.register_for_function("EVM Print stack",
                                    "Print up to 10 values of the stack",
                                    function_printStack_start,
                                    is_valid=is_valid_evm)

PluginCommand.register("EVM Annotate Instructions",
                       "EVM Annotate Instructions",
                       annotator.annotate_all,
                       is_valid=is_valid_evm)

PluginCommand.register(
        "EVM Rename functions (4byte.directory)",
        "Perform lookup of all hash signatures on 4byte.directory to rename unknown functions",
        lookup4byte.rename_all_functions,
        is_valid=is_valid_evm)

PluginCommand.register_for_address(
        "EVM Lookup 4byte hash (4byte.directory)",
        "Perform lookup of one hash signature on 4byte.directory",
        lookup4byte.lookup_one_inst,
        is_valid=is_valid_evm)


EVM.register()
EVMView.register()
