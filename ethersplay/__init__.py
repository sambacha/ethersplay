from binaryninja import PluginCommand, Architecture

from .coverage import function_coverage_start
from .evm import EVM, EVMView
from .flowgraph import render_flowgraphs
from .annotator import annotate_all
from .lookup4byte import (rename_all_functions, lookup_one_inst,
                          update_cache_bn)


def is_valid_evm(view, function=None):
    return view.arch == Architecture['EVM']


PluginCommand.register(
    r"Ethersplay\Manticore Highlight",
    "EVM Manticore Highlight",
    function_coverage_start,
    is_valid=is_valid_evm)

PluginCommand.register(
    r'Ethersplay\Render Flowgraphs',
    'Render flowgraphs of every function, removing stack variable annotations',
    render_flowgraphs,
    is_valid=is_valid_evm)

# non-upstream things
PluginCommand.register(
    "Ethersplay\\Annotate Instructions",
    "[EVM] Annotate Instructions",
    annotate_all,
    is_valid=is_valid_evm)

PluginCommand.register(
    "Ethersplay\\Rename functions (4byte.directory)",
    "Perform lookup of all hash signatures on 4byte.directory to rename unknown functions",
    rename_all_functions,
    is_valid=is_valid_evm)

PluginCommand.register(
    "Ethersplay\\update cashed function hashes (4byte.directory)",
    "Re-do lookup of all hash signatures on 4byte.directory, which are stored in the local cache.",
    update_cache_bn,
    is_valid=is_valid_evm)

PluginCommand.register_for_address(
    "Ethersplay\\Lookup 4byte hash (4byte.directory)",
    "Perform lookup of one hash signature on 4byte.directory",
    lookup_one_inst,
    is_valid=is_valid_evm)

EVM.register()
EVMView.register()
