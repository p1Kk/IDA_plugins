
#include <idc.idc>

// 输入：
//   ea=起始有效地址
// 输出：
//   返回未命名代码片段有效地址；如果没找到，则返回BADADDR。
static JumpNotFunction(ea)
{
  auto name;
  do {
    if (!isCode(GetFlags(ea)) || Byte(ea) == 0x90 || Byte(ea) == 0xCC) // 过滤无效代码
      ea = FindCode(ea,SEARCH_DOWN);
    name = GetFunctionName(ea);
    if (name == "" && ea != BADADDR) // 如果找到未定义函数，就跳转到该有效地址
    {
      Jump(ea);
    }
    else
      ea = FindFuncEnd(ea); // 如果是一定义函数，继续查找
  } while(name != "" && ea != BADADDR);
  return ea;
}

// 利用JumpNotFunction解决问题
static main(void)
{
  auto ea0,ea,ea_end,fok;
  ea0 = ScreenEA(); // 记住当前光标位置
  ea=MinEA(); // 从头开始
  ea_end = SegEnd(ea); // 防止地址越界
  Message("ea0=%lx\n",ea);
  do{
    ea = JumpNotFunction(ea); // 调用刚建立的函数
    if (ea != BADADDR)
      fok = MakeFunction(ea,BADADDR);
    if (!fok) {
      ea = FindFuncEnd(ea);
      Jump(ea);
    }
  } while (ea < ea_end && ea != BADADDR);
  Jump(ea0); // 恢复光标位置
}
