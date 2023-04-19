import idc
import idaapi
import idautils
import ida_kernwin

# 遍历所有的代码段
for seg in idautils.Segments():
    # 获取当前代码段的结束地址
    seg_end = idaapi.getseg(seg).end_ea
    # 遍历当前代码段内的所有指令
    for head in idautils.Heads(seg, seg_end):
        # 获取当前指令的地址
        ea = head
        # 如果当前地址不是一个函数的入口地址
        if not idaapi.get_func(ea):
            # 定义一个新的函数，该函数的起始地址为当前地址
            idaapi.add_func(ea)
            # 刷新函数窗口，以便可以在函数列表中看到新函数
            idaapi.refresh_idaview_anyway()
