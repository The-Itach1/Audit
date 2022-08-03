# -*- coding: utf-8 -*-

# reference
# 《ida pro 权威指南》
# 《python 灰帽子》
# 《家用路由器0day漏洞挖掘》
# https://github.com/wangzery/SearchOverflow/blob/master/SearchOverflow.py

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

DEBUG = True

# fgetc,fgets,fread,fprintf,
# vspritnf

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

    #print(hex(addr))
    if(idc.get_operand_type(addr ,op_num) != 5):
        op_num = op_num + 1
    if idc.get_operand_type(addr ,op_num) != 5:
        return "get fail"

    op_string = print_operand(addr, op_num).split(" ")[0].split("+")[0].split("-")[0].replace("(", "")
    string_addr = idc.get_name_ea_simple(op_string)
    if string_addr == BADADDR:
        return "get fail"
    string = str(get_strlit_contents(string_addr, -1, STRTYPE_TERMCHR))
    return [string_addr, string ,op_string]


def get_Tpye_ArgAddr(start_addr, regNum, argType):
    mipscondition = ["bn", "be" , "bg", "bl"]
    scan_deep = 80
    count = 0
    reg = argType + str(regNum)

    # try to get before
    before_addr = get_first_cref_to(start_addr)
    while before_addr != BADADDR:
        if reg == print_operand(before_addr, 0):
            Mnemonics = print_insn_mnem(before_addr)
            if Mnemonics[0:2] in mipscondition:
                pass
            elif Mnemonics[0:1] == "j":
                pass
            else:
                return before_addr
        count = count + 1
        if count > scan_deep:
            break
        before_addr = get_first_cref_to(before_addr)
    return BADADDR


def getArg(start_addr, regNum):
    mipsmov = ["move", "lw", "li", "lb", "lui", "lhu", "lbu", "la"]
    arg_addr = get_Tpye_ArgAddr(start_addr, regNum, "$a")
    if arg_addr != BADADDR:
        Mnemonics = print_insn_mnem(arg_addr) 
        if Mnemonics[0:3] == "add":
            if print_operand(arg_addr, 2) == "":
                arg = print_operand(arg_addr, 0) + "+" + print_operand(arg_addr, 1)
            else:
                arg = print_operand(arg_addr, 1) + "+" +  print_operand(arg_addr, 2)
        elif Mnemonics[0:3] == "sub":
            if print_operand(arg_addr, 2) == "":
                arg = print_operand(arg_addr, 0) + "-" + print_operand(arg_addr, 1)
            else:
                arg = print_operand(arg_addr, 1) + "-" +  print_operand(arg_addr, 2)
        elif Mnemonics in mipsmov:
            arg = print_operand(arg_addr, 1) 
        else:
            arg = idc.generate_disasm_line(arg_addr,1).split("#")[0]
        set_cmt(arg_addr, "addr: 0x%x " % start_addr  + "-------> arg" + str((int(regNum)+1)) + " : " + arg, 0)
        return arg
    else:
        return "get fail"

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

    # get first call
    call_addr = get_first_cref_to(func_addr)
    while call_addr != BADADDR:
        idc.set_color(call_addr, idc.CIC_ITEM, 0xffff00)
        Mnemonics = print_insn_mnem(call_addr)
        if Mnemonics[0:1] == "j" or Mnemonics[0:1] == "b":
            if func_name in format_function_offset_dict:
                info = auditFormat(call_addr, func_name, arg_num)
            else:
                info = auditAddr(call_addr, func_name, arg_num)
            table.add_row(info)
        call_addr = get_next_cref_to(func_addr, call_addr)
    print(table)

def auditAddr(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = idc.get_func_attr(call_addr , idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        print("debug 236")
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in range(0,arg_num):
        ret_list.append(getArg(call_addr, num)) 
    ret_list.append(local_buf_size)
    return ret_list

def auditFormat(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = idc.get_func_attr(call_addr , idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        print("debug 252")
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in range(0,arg_num):
        ret_list.append(getArg(call_addr, num)) 
    mid_arg_addr = get_Tpye_ArgAddr(call_addr, format_function_offset_dict[func_name], "$a")
    xx_arg=getArg(call_addr,format_function_offset_dict[func_name])

    if xx_arg in ['$v0','$v1','$v2']:
        true_arg_addr = get_Tpye_ArgAddr(mid_arg_addr, int(xx_arg[-1]),"$v")
    elif xx_arg in ['$s1','$s0']:
        true_arg_addr = get_Tpye_ArgAddr(mid_arg_addr, int(xx_arg[-1]), "$s")
    elif xx_arg in ["$a0","$a1","$a2"] and int(xx_arg[-1])!= format_function_offset_dict[func_name]:
        true_arg_addr = get_Tpye_ArgAddr(mid_arg_addr, int(xx_arg[-1]), "$a")
    else:
        true_arg_addr=mid_arg_addr
    string_and_addr =  getFormatString(true_arg_addr)

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
        # mips arg reg is from a0 to a3
        if fmt_num + arg_num >= 4:
            fmt_num = 4
        else:
            fmt_num = fmt_num + arg_num
        for num in range(arg_num, fmt_num):
            format_and_value.append(getArg(call_addr, num))
        ret_list.append(format_and_value)
    ret_list.append(local_buf_size)
    return ret_list

def MipsAudit():
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

class MipsAudit_Plugin_t(idaapi.plugin_t):
    comment = "MIPS Audit plugin for IDA Pro"
    help = "todo"
    wanted_name = "MipsAudit"
    wanted_hotkey = "Ctrl-Alt-M"
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global m_initialized

        if m_initialized is False:
            m_initialized = True
            print("=" * 80)
            start = '''
             __  __ _              _             _ _ _   
            |  \/  (_)_ __  ___   / \  _   _  __| (_) |_ 
            | |\/| | | '_ \/ __| / _ \| | | |/ _` | | __|
            | |  | | | |_) \__ \/ ___ \ |_| | (_| | | |_ 
            |_|  |_|_| .__/|___/_/   \_\__,_|\__,_|_|\__|
                     |_|                                 
                     
                            re-edit by The_Itach1  2022.8.3
            '''
            print(start)
            print("=" * 80)

            return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        info = idaapi.get_inf_structure()
        if 'mips' in info.procName:
            MipsAudit()
        else:
            print('MipsAudit is not supported on the current arch')

def PLUGIN_ENTRY():
    return MipsAudit_Plugin_t()

if __name__ == '__main__':
    MipsAudit()