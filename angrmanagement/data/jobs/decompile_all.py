from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.logic import GlobalInfo

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class DecompileAllJob(InstanceJob):
    """
    The job for running the decompiler analysis on all functions in address-sorted order.
    You can trigger this by pressing Shift+F5.
    """

    def __init__(self, instance: Instance, on_finish=None, blocking: bool = False, **kwargs) -> None:
        super().__init__("Decompiling All Functions", instance, on_finish=on_finish, blocking=blocking)
        self.kwargs = kwargs

    def run(self, ctx: JobContext) -> bool:

        self.instance.project.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True)

        functions = sorted(self.instance.kb.functions)

        total = len(functions)
        for idx, func_addr in enumerate(functions):
            func = self.instance.kb.functions[func_addr]

            if func is None or func.is_plt or func.is_syscall or func.is_alignment or func.is_simprocedure:
                continue

            ctx.set_progress((idx + 1) / total * 100)

            try:
                dec = self.instance.project.analyses.Decompiler(
                    func,
                    flavor="pseudocode",
                    variable_kb=self.instance.pseudocode_variable_kb,
                    **self.kwargs,
                    progress_callback=ctx.set_progress,
                )
                self.instance.kb.decompilations[(func.addr, "pseudocode")] = dec.cache

            except Exception:
                pass

        GlobalInfo.main_window.workspace.plugins.decompile_callback(None)

        return True
