import idc
import idaapi
import idautils
import ida_kernwin

# 针对arm32 函数开头普遍为【MOV r12, sp】创建函数
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
            # 判断当前指令是否为mov r12, sp;
            insn = DecodeInstruction(ea)
            if insn and insn.get_canon_mnem() == "MOV" and insn.Op1.type == o_reg and insn.Op1.reg == 12 and insn.Op2.type == o_reg and insn.Op2.reg == 13:
                # 定义一个新的函数，该函数的起始地址为当前地址
                idaapi.add_func(ea)
                print("Create Function at 0x%x" % ea)
                
# 刷新函数窗口，以便可以在函数列表中看到新函数
# idaapi.refresh_idaview_anyway()
print("Done!")
