from idaapi import *
import idaapi
import idc
from prettytable import PrettyTable

if idaapi.IDA_SDK_VERSION > 700:
    import ida_search
    from idc import (
        print_operand
    )
    from ida_bytes import (
        get_strlit_contents
    )
else:
    from idc import (
        GetOpnd as print_operand,
        GetString
    )
    def get_strlit_contents(*args): return GetString(args[0])

# set function_name
dangerous_functions = [
    "strcpy",
     "strcat",
    "sprintf",
     "read",
     "getenv"
]

attention_function = [
    "memcpy",
    "malloc",
    "strncpy",
    "sscanf",
    "strncat",
    "snprintf",
    "vprintf",
    "printf"
]

command_execution_function = [
    "system",
    "execve",
    "popen",
    "unlink"
]


# describe arg num of function

one_arg_function = [
    "malloc",
    "getenv",
    "system",
    "unlink"
]

two_arg_function = [
    "strcpy",
    "strcat",
    "popen"
]

three_arg_function = [
    "strncpy",
    "strncat",
    "memcpy",
    "execve",
    "read"
]

format_function_offset_dict = {
    "sprintf":1,
    "sscanf":1,
    "snprintf":2,
    "vprintf":0,
    "printf":0
}


def printFunc(func_name):
    string1 = "========================================"
    string2 = "========== Auditing " + func_name + " "
    strlen = len(string1) - len(string2)
    return string1 + "\n" + string2 + '=' * strlen + "\n" + string1

def getFuncAddr(func_name):
    func_addr = idc.get_name_ea_simple(func_name)
    if func_addr != BADADDR:
        print(printFunc(func_name))
        return func_addr
    return False


def getArgAddr(start_addr, regNum):
    armcondition=[]

    #大部分，这个深度是够的，但是仍有小部分超过这个范围
    scan_deep = 100
    count = 0
    reg = "R" + str(regNum)

    # try to get before
    before_addr = get_first_cref_to(start_addr)
    while before_addr != BADADDR:
        if (reg == idc.print_operand(before_addr, 0)):
            Mnemonics = print_insn_mnem(before_addr)
            if Mnemonics[0:2] in armcondition:
                pass
            if Mnemonics[0:1] =="B":
                pass
            else:
                return before_addr
        count = count + 1
        if count > scan_deep:
            break
        before_addr = get_first_cref_to(before_addr)
    return BADADDR



def getArg(start_addr, regNum):
    arm=['LDR','CMP','STR','MOV']
    arg_addr = getArgAddr(start_addr, regNum)

    if arg_addr != BADADDR:
        Mnemonics = idc.print_insn_mnem(arg_addr)
        if Mnemonics[0:3] == "ADD":
            pc_rx_str = idc.print_operand(arg_addr, 1) + "+" +  idc.print_operand(arg_addr, 2)
            if pc_rx_str[0:4]=="PC+R":
                mid_addr=getArgAddr(arg_addr,int(pc_rx_str[-1]))
                arg =  idc.print_operand(arg_addr, 1) + "+" + idc.print_operand(mid_addr, 1)
            else:
                arg = pc_rx_str
        elif Mnemonics[0:3] == "SUB":
            arg = idc.print_operand(arg_addr, 1) + "-" +  idc.print_operand(arg_addr, 2)
        elif Mnemonics[0:3] in arm:
            arg = idc.print_operand(arg_addr, 1)
        else:
            arg = idc.generate_disasm_line(arg_addr,1).split(" ")[0]
        set_cmt(arg_addr, "addr: 0x%x " % start_addr  + "-------> arg" + str((int(regNum)+1)) + " : " + arg, 0)
        return arg
    else:
        return "get fail"
#-------------------------------------------------------------------#



def auditAddr(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = idc.get_func_attr(call_addr , idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR:
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in range(0,arg_num):
        ret_list.append(getArg(call_addr, num))
    ret_list.append(local_buf_size)
    return ret_list


#-------------------------------------------------------------------#


def getFormatString(addr):
    op_num = 1
    # idc.get_operand_type Return value
    #define o_void        0  // No Operand                           ----------
    #define o_reg         1  // General Register (al, ax, es, ds...) reg
    #define o_mem         2  // Direct Memory Reference  (DATA)      addr
    #define o_phrase      3  // Memory Ref [Base Reg + Index Reg]    phrase
    #define o_displ       4  // Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    #define o_imm         5  // Immediate Value                      value
    #define o_far         6  // Immediate Far Address  (CODE)        addr
    #define o_near        7  // Immediate Near Address (CODE)        addr
    #define o_idpspec0    8  // IDP specific type
    #define o_idpspec1    9  // IDP specific type
    #define o_idpspec2   10  // IDP specific type
    #define o_idpspec3   11  // IDP specific type
    #define o_idpspec4   12  // IDP specific type
    #define o_idpspec5   13  // IDP specific type
    # 如果第二个不是立即数则下一个
#.split("+")[0].split("-")[0].replace("(", "")
    if(idc.get_operand_type(addr ,op_num) != 2):
        op_num = op_num + 1
    if idc.get_operand_type(addr ,op_num) != 2:
        return "get fail"

    op_string = idc.print_operand(addr, op_num).split(" ")[0].replace("=(", "")
    if('+0x' in op_string):
        offset=op_string.split("+")[1]
        op_string=op_string.split("+")[0]
        string_addr = idc.get_name_ea_simple(op_string)
        string_addr=string_addr+int(offset, 16)
    else:
        string_addr = idc.get_name_ea_simple(op_string)
    if string_addr == BADADDR:
        return "get fail"
    string = str(get_strlit_contents(string_addr, -1, STRTYPE_TERMCHR))
    return [string_addr, string, op_string]


def auditFormat(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = idc.get_func_attr(call_addr , idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in range(0,arg_num):
        ret_list.append(getArg(call_addr, num))
    mid_arg_addr = getArgAddr(call_addr, format_function_offset_dict[func_name])
    Rx_arg=getArg(call_addr,format_function_offset_dict[func_name])

    if Rx_arg in ['R9','R11','R4','R6','R10']:
        if len(Rx_arg)==2:
            true_arg_addr=getArgAddr(mid_arg_addr,int(Rx_arg[-1]))
            true_arg_addr=getArgAddr(true_arg_addr,int(Rx_arg[-1]))
        else:
            true_arg_addr = getArgAddr(mid_arg_addr, int(Rx_arg[1:]))
            true_arg_addr = getArgAddr(true_arg_addr, int(Rx_arg[1:]))
    else:
        true_arg_addr=getArgAddr(mid_arg_addr,format_function_offset_dict[func_name])
    string_and_addr =  getFormatString(true_arg_addr)

    if Rx_arg in ['R9','R11','R4','R6','R10']:
        format_arg=string_and_addr[2]
        ret_list.pop(-1)
        ret_list.append(format_arg)

    format_and_value = []
    if string_and_addr == "get fail":
        ret_list.append("get fail")
    else:
        string_addr = "0x%x" % string_and_addr[0]
        format_and_value.append(string_addr)
        string = string_and_addr[1]
        fmt_num = string.count("%")
        format_and_value.append(fmt_num)
        # mips arg reg is from R0 to R3
        if fmt_num + arg_num >= 4:
            fmt_num = 4
        else:
            fmt_num=fmt_num+arg_num
        for num in range(arg_num,fmt_num):
            format_and_value.append(getArg(call_addr, num))
        ret_list.append(format_and_value)
    ret_list.append(local_buf_size)
    return ret_list


def audit(func_name):
    func_addr = getFuncAddr(func_name)
    if func_addr == False:
        return False

    # get arg num and set table
    if func_name in one_arg_function:
        arg_num = 1
    elif func_name in two_arg_function:
        arg_num = 2
    elif func_name in three_arg_function:
        arg_num = 3
    elif func_name in format_function_offset_dict:
        arg_num = format_function_offset_dict[func_name] + 1
    else:
        print("The %s function didn't write in the describe arg num of function array,please add it to,such as add to `two_arg_function` arary" % func_name)
        return

    table_head = ["func_name", "addr"]
    for num in range(0,arg_num):
        table_head.append("arg"+str(num+1))

    if func_name in format_function_offset_dict:
        table_head.append("format&value[string_addr, num of '%', fmt_arg...]")
    table_head.append("local_buf_size")
    table = PrettyTable(table_head)

    #循环遍历调用当前函数的地址
    call_addr = get_first_cref_to(func_addr)
    while call_addr != BADADDR:
        idc.set_color(call_addr, idc.CIC_ITEM, 0xffff00)
        #获取当前地址的指令
        Mnemonics = print_insn_mnem(call_addr)
        if Mnemonics[0:1] == "B":
            if func_name in format_function_offset_dict:
                info = auditFormat(call_addr, func_name, arg_num)
            else:
                info = auditAddr(call_addr, func_name, arg_num)
            table.add_row(info)
        call_addr = get_next_cref_to(func_addr, call_addr)
    print(table)



def ArmAudit():
    # the word create with figlet
    print("Auditing dangerous functions ......")
    for func_name in dangerous_functions:
        audit(func_name)

    print("Auditing attention function ......")
    for func_name in attention_function:
        audit(func_name)

    print("Auditing command execution function ......")
    for func_name in command_execution_function:
        audit(func_name)

    print("Finished! Enjoy the result ~")

m_initialized = False

class ArmAudit_Plugin_t(idaapi.plugin_t):
    comment = "ARM Audit plugin for IDA Pro" # 描述信息
    help = "todo" # 帮助信息
    wanted_name = "ArmAudit" # 菜单中显示的名字
    wanted_hotkey = "Ctrl-Alt-A" # 希望注册的快捷键
    flags = idaapi.PLUGIN_KEEP # 插件的状态, 当前状态保持在Plugin菜单中

    def init(self):
        global m_initialized

        if m_initialized is False:
            m_initialized = True
            print("=" * 80)
            start = '''
            _                      _             _ _ _   
           / \   _ __ _ __ ___    / \  _   _  __| (_) |_ 
          / _ \ | '__| '_ ` _ \  / _ \| | | |/ _` | | __|
         / ___ \| |  | | | | | |/ ___ \ |_| | (_| | | |_ 
        /_/   \_\_|  |_| |_| |_/_/   \_\__,_|\__,_|_|\__|

                            re-edit by The_Itach1  2022.8.3
            '''
            print(start)
            print("=" * 80)

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        '''
                    每次运行插件时, 执行的具体操作
                    功能代码在此编写
        '''

        info = idaapi.get_inf_structure()
        if 'ARM' in info.procName:
            ArmAudit()
        else:
            print('ArmAudit is not supported on the current arch')

def PLUGIN_ENTRY():
    '''
            插件入口,用于实例对象
            返回的就是插件的功能等
    '''
    return ArmAudit_Plugin_t()

if __name__ == '__main__':
    ArmAudit()