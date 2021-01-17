from binaryninja import PluginCommand, Architecture

from .coverage import function_coverage_start
from .evm import EVM, EVMView
from .flowgraph import render_flowgraphs
from .annotator import annotate_all
from .lookup4byte import (rename_all_functions, lookup_one_inst,
                          update_cache_bn, lookup_all_push4)
from .misc import dump_codecopy_data

def is_valid_evm(view, function=None):
    return view.arch == Architecture["EVM"]


PluginCommand.register(
    r"Ethersplay\Manticore Highlight",
    "EVM Manticore Highlight",
    function_coverage_start,
    is_valid=is_valid_evm,
)

PluginCommand.register(
    r"Ethersplay\Render Flowgraphs",
    "Render flowgraphs of every function, removing stack variable annotations",
    render_flowgraphs,
    is_valid=is_valid_evm,
)

EVM.register()
EVMView.register()
