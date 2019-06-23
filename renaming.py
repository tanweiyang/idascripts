import csv
import sys
import idc


class Renamer:
    """
    This class is to rename or insert comments based on the input csv config 
    file.
    """
    
    def __init__(self):
        self._comment_tag = "[" + __file__ + "]" 
        self._marked_pos_slot = 




# This tag will be used for all comments generated.
COMMENT_TAG = "[" + __file__ + "]" 


def update_found_addr(found_addr, found_addr_set):
    """
    Args:
        found_addr: To be added or update into found_addr_set.
        found_addr_set: Set containing all the found addresses so far.
        first_run: Is this the first time updating? If so, just add, else intersection.
    """
    if(found_addr == idc.BADADDR):
        return

    found_addr_set.add(found_addr)


def mark_pos_cmt(cmd, value):
    """
    Args:
        cmd: The command type.
        value: The value for the command.
    Returns:
       The comment string for the marked position. 
    """
    return COMMENT_TAG + ": " + cmd + " (" + value + ")"


def get_next_marked_pos_slot(start_num = 0):
    """
    Get the next empty slot number for marking position.

    Args:
        start_num: Start checking the slots from start_num.

    Returns:
        The next empty slot number for marking position.
    """
    max_slot = 1024;
    while(start_num <= max_slot):
        if(ida_idc.get_marked_pos(start_num) == idc.BADADDR):
            return start_num
    
        start_num += 1

    print("Cannot find an empty slot for marking position!")
    exit(1)


def process_cond(cond_type, cond_value, start_addr):
    """
    Args:
        cond_type: The condition type.
        cond_value: The value for the condition.
        start_addr: The starting address for searching.

    Returns:
        A tuple of (<frozen_set_of_found_addr>,<next_search_addr>).
    """
    search_flag = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT
    found_addr = start_addr
    if(cond_type == "refStr"):
        found_addr = ida_search.find_text(start_addr,
                                          0,
                                          0,
                                          cond_value,
                                          search_flag)
        start_addr = idc.next_head(found_addr)
        found_addr_set = frozenset(idautils.DataRefsTo(found_addr))
        print("hasStr matched!!! found_addr: {0} found_addr_set: {1}, start_addr: {2} cond_value: {3}".format(found_addr, found_addr_set, start_addr, cond_value))

    elif(cond_type == "hasBytes"):
        found_addr = idc.find_binary(start_addr,
                                     search_flag,
                                     cond_value)
        start_addr = found_addr
        found_addr_set = frozenset([found_addr])

    elif(cond_type == "addr"):
        found_addr_set = frozenset(int(cond_value, 16)) # note that cond_value is a string

    else:
        print("Condition type: {0} is not supported!".format(cond_type))
        exit(1)

    return (found_addr_set, start_addr)


def retrieve_ea_list_set(cond_list):
    """
    Args:
        cond_list: List of conditions to determine the address.

    Returns:
        A list of set of found addresses. Each set of addresses corresponds to a condition.
    """
    found_addr_list_set = []    # List of set of found addresses.

    for cond in cond_list:
        print("{0}".format(cond))
        split_cond = cond.split(':')
        
        if(len(split_cond) != 2):
            print("Condition is malformed. It should be of form <type>:<value> but I am getting {0}".format(split_cond))
            exit(1)

        cond_type = split_cond[0]
        cond_value = split_cond[1]

        curr_addr = idc.get_inf_attr(INF_MIN_EA) # Get start of addr of entire binary
        end_addr = idc.get_inf_attr(INF_MAX_EA) # Get end of addr of entire binary

        cond_found_addr_set = set()
        while(curr_addr < end_addr):
            (result_addr_set, curr_addr) = process_cond(cond_type, cond_value, curr_addr)
            cond_found_addr_set |= result_addr_set
            print("cond_found_addr_set: {0} result_addr_set: {1}".format(cond_found_addr_set, result_addr_set))   

        found_addr_list_set.append(cond_found_addr_set)

    return found_addr_list_set


def process_cmd(cmd, val, ea_list_set):
    """
    Process the command.

    Args:
        cmd: The command type.
        val: The value for the command.
        ea_list_set: List of set of found addresses based on the conditions, where each set of addresses corresponds to a condition.

    Returns:
        True if process the command successfully; False otherwise.
    """
    if(cmd == "RF"): # Rename function
        func_to_be_renamed_addr = 0
        found_func_set = set()

        # First round just add to empty set.
        ea_set = ea_list_set.pop()
        print("ea_set: {0}".format(ea_set))

        # First iteration just add into the set.
        found_func_set_tmp = set()
        for addr in ea_set:
            found_func_set.add(ida_funcs.get_func(addr))
            print("found_func_set: {0}!".format(found_func_set))

        # Subsequent iterations perform intersection.
        for ea_set in ea_list_set:
            found_func_set_tmp = set()
            for addr in ea_set:
                found_func_set_tmp.add(ida_funcs.get_func(addr))
                print("found_func_set_tmp: {0}!".format(found_func_set_tmp))

            found_func_set &= found_func_set_tmp

        if(len(found_func_set) != 1):
            print("Functions to be renamed is not 1 but {0}! Check again.".format(len(found_func_set)))
            exit(1)

        func_addr = found_func_set.pop().startEA
        idc.set_name(func_addr, val, ida_name.SN_CHECK)
        ida_idc.mark_position(func_addr, 0, 0, 0, get_next_marked_pos_slot(), mark_pos_cmt(cmd, val))

    else:
        print("The command {0} is not supported yet.".format(cmd))
        exit(1)
        return False

    return True


def process_entry(csv_row):
    """
    Args:
        csv_row: A list of data in the form of
                 <cmd>,<value>,<cond1;cond2>
    """
    # Each entry must have at least 3 items.
    if(len(csv_row) < 3):
        print("CSV file is malformed. Entry: {0} must have at least 3 fields".format(csv_row))
        exit(1)

    cmd = csv_row[0]
    val = csv_row[1]
    cond_list = csv_row[2].split(';')

    print("cmd: {0}, val: {1}, cond_list: {2}".format(cmd, val, cond_list))

    ea_list_set = retrieve_ea_list_set(cond_list)
    if(len(ea_list_set) == 0):
        print("Error: Cannot find any satisfied condition")
        exit(1)

    process_cmd(cmd, val, ea_list_set) 


def read_csv_file(datafile):
    """
    Args:
        datafile: Input csv file path.

    Returns:
        
    """
    with open(datafile, 'r') as csvfileobj:
        csvreader = csv.reader(csvfileobj, delimiter=',')
        for row in csvreader:
            process_entry(row)



read_csv_file("my.csv")

