import sys
import re
from abc import ABCMeta, abstractmethod


###############################################################################
# Generic Search All Instruction Function
###############################################################################
class Search_Func_Insn:
    """
    This is an abstract base class. 
    It will help traverse through all the instructions of the function and 
    invoke _action_on_insn(), which the child class should override it.

    """

    __metaclass__ = ABCMeta


    def __init__(self, curr_func_addrs):
        """
        Args:
            curr_func_addrs: Set of function addresses which you will start searching.
                             Type: iterable of ea_t
        """
        self.__curr_funcs = set()
        for ea in curr_func_addrs:
            self.__curr_funcs.add(ida_funcs.get_func(ea))


    @staticmethod
    def _print_highlight_2tup_lists(to_print_list, color):
        """
        Print the list of 2-tuple list (first element is address)

        Args:
            to_print_list: The list of addresses to be printed.
            color: 
        """
        for (ea, s) in to_print_list:
            print("{0}: {1}".format(hex(ea), s))
            idc.set_color(ea, CIC_ITEM, color)


    @abstractmethod
    def _action_on_insn(self, insn):
        """
        This function is to be overriden by child classes. The current function
        will always return true.

        Args:
            insn: The instruction you are going to process. Type is insn_t.
        """
        print("This is an empty _action_on_insn(). Need to be overriden.")


    def start(self):
        """
        Start the searching.
        """
        for curr_func in self.__curr_funcs:
            curr_addr = curr_func.start_ea
            end_addr = curr_func.end_ea

            while(curr_addr <= end_addr):
                curr_addr = idc.next_head(curr_addr)

                insn_out = ida_ua.insn_t()
                ida_ua.decode_insn(insn_out, curr_addr)

                # Clear highlighting too if any
                idc.set_color(curr_addr, idc.CIC_ITEM, 0xffffff)

                self._action_on_insn(insn_out)



###############################################################################
# Search For Strings References In The Function
###############################################################################
class String_Finder(Search_Func_Insn):
    """
    This class will help instructions that references strings that matches
    your pattern.

    The class has a private variable: __results, which takes in a list of addrs
    and the corresponding strings
    """
    def __init__(self, curr_func_addrs, str_pat):
        """
        Args:
            curr_func_addr: Addresses of the functions which you will start 
                            searching.
                            Type: ea_t

            str_pat: The string regex pattern you will be matching.
        """
        Search_Func_Insn.__init__(self, curr_func_addrs)
        self.__results = list()
        self.__pattern = re.compile(str_pat)


    def _action_on_insn(self, insn):
        """
        This function will look for referenced strings matching the pattern.

        Args:
            insn: The instruction you are going to process. Type is insn_t.
        """
#        for op in list(insn.ops):
#            if(op.type == ida_ua.o_void):
#                break
#
#            #if(op.type == ida_ua.o_imm):
#            # how to know this is a string
#            print("insn.ea: {0} op.type: {1} is imm? {2}".format(hex(insn.ea), op.type, ida_ua.o_imm == op.type))
#            print("op value: {0} op addr: {1}, Str: {2}".format(hex(op.value), hex(op.addr), ida_bytes.get_strlit_contents(op.value, -1, ida_nalt.STRTYPE_C)))
        line = idc.GetDisasm(insn.ea)
        line_comment = line[line.find(';'):]
        if(self.__pattern.search(line_comment) and line[0:4] == "ADRP"):
            self.__results.append((insn.ea, line_comment))


    def print_matched_strings(self):
        print("=== Strings ==== ")
        Search_Func_Insn._print_highlight_2tup_lists(self.__results, 0x00ffff)
        print("")



###############################################################################
# Search For Calls In The Function
###############################################################################
class Call_Finder(Search_Func_Insn):
    """
    This class will help find direct and indirect calls and jumps.

    """
    def __init__(self, curr_func_addrs):
        """
        Args:
            curr_func_addr: Addresses of the functions which you will start 
                            searching.
                            Type: ea_t
        """
        Search_Func_Insn.__init__(self, curr_func_addrs)
        self.__direct_calls = [] 
        self.__direct_calls_dest_set = set()
        self.__indirect_calls = []
        self.__jumps = []


    @staticmethod
    def __dest_func_is_useful(insn):
        """
        Returns True if the call to this function is, as of now, not lib func.

        Args:
            insn: The instruction of the direct call. Type is insn_t.
        """
        func_addr = insn.Op1.addr
        func_flags = ida_funcs.get_func(func_addr).flags

        return not (func_flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK))


    def _action_on_insn(self, insn):
        """
        This function will look for calls and jumps.

        Args:
            insn: The instruction you are going to process. Type is insn_t.
        """
        canon_feature = insn.get_canon_feature()
        canon_mnem = insn.get_canon_mnem()

        if(ida_idp.CF_CALL & canon_feature):
            if(canon_mnem == "BL"):
                if(Call_Finder.__dest_func_is_useful(insn)):
                    self.__direct_calls.append((insn.ea, idc.GetDisasm(insn.ea))) 
                    self.__direct_calls_dest_set.add(insn.Op1.addr)
            elif(canon_mnem == "BLR"):
                self.__indirect_calls.append((insn.ea, idc.GetDisasm(insn.ea)))

        if(ida_idp.CF_JUMP & canon_feature): # note that branches "B" will not be stored here
            self.__jumps.append((insn.ea, idc.GetDisasm(insn.ea)))


    def print_direct_calls_addr(self):
        print("=== Direct calls ==== ")
        Search_Func_Insn._print_highlight_2tup_lists(self.__direct_calls, 0x00ffff)
        print("")


    def print_direct_calls_dest(self):
        print("=== Direct calls to non-trivial functions ==== ")
        for ea in self.__direct_calls_dest_set:
            print("Addr: {0} Func name: {1}".format(hex(ea), idc.get_func_name(ea)))
        print("")


    def print_indirect_calls_addr(self):
        print("=== Indirect calls ==== ")
        Search_Func_Insn._print_highlight_2tup_lists(self.__indirect_calls, 0xffff00)
        print("")


    def print_jumps_addr(self):
        print("=== Jumps ==== ")
        Search_Func_Insn._print_highlight_2tup_lists(self.__jumps, 0xff00ff)
        print("")


    def print_result(self):
        self.print_indirect_calls_addr()
        self.print_jumps_addr()
        self.print_direct_calls_dest()


###############################################################################
# APIs
###############################################################################
def find_calls_in_curr_fn():
    """
    Print all the calls instructions in the current address.
    """
    finder = Call_Finder(frozenset([idc.here()]))
    finder.start()
    finder.print_result()    


def find_str_in_curr_fn(pattern=';'):
    """
    Print all the instructions referencing strings. Note that this is using the
    heuristic of looking for ADRP mnemonic and the generated comment by IDA.

    Args:
        pattern: The regex pattern that you want to match against.
    """
    finder = String_Finder(frozenset([idc.here()]), pattern)
    finder.start()
    finder.print_matched_strings()


def find_dref_to_fns():
    """
    List all the functions in the text segment that has data xref to. This is
    for searching the functions that will be invoked via BLR.

    Return:
        Set of function addresses that have data xref.
    """
    results = set()
    text_seg = ida_segment.get_segm_by_name(".text")
    text_seg_end_ea = text_seg.end_ea
    text_seg_start_ea = text_seg.start_ea
    
    ea = text_seg_start_ea

    while(ea < text_seg_end_ea):
        dref_to_ea = ida_xref.get_first_dref_to(ea)

        # You will want to check that the dref is within the range of 
        # text segment too
        if(dref_to_ea != ida_idaapi.BADADDR and
           dref_to_ea <= text_seg_end_ea and
           dref_to_ea >= text_seg_start_ea):
            #print("{0} has cref: {1}".format(ea, hex(ida_xref.get_first_cref_to(ea))))
            print("{0} -> {1}: {2}".format(hex(ea), hex(dref_to_ea), ida_ua.print_insn_mnem(dref_to_ea)))
            results.add(ea)

        ea = ida_funcs.get_next_func(ea).start_ea

    return results


def patch_dref_to_fns(filename):
    """
        Take in the file which is in the format of:
            <fn addr>: <list of link register addresses>

        And then patch the IDB by adding in the data xref at the assembly line 
        of the functions.
    """
    with open(filename, "r") as fh:
        for line in fh:
            split_str = line.split(':')
            fn_addr = long(split_str[0].strip(), 0)
            
            dref_list = split_str[1].split(',')
            for dref in dref_list:
                dref = dref.strip()
                if(dref):
                    to_dref_addr = long(dref.strip(), 0) - 4 # 
                    ida_xref.add_dref(to_dref_addr, fn_addr, ida_xref.XREF_DATA)

