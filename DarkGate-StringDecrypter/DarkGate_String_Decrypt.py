__author__ = "Zachary Reichert, Aon Cyber Solutions"

import idautils
import ida_funcs
import idaapi
  
  
class DecryptorError(Exception):
    pass
  
def custom_base64_decode(encoded_string):
    '''
    # The function "custom_base64_decode" decodes the argument via the base64 algorithm with the custom base64 alphabet of BHUPY4TaCANpsdt2zx9yXEnVkmcgl58wGbIRWSreJuKQO7fqLF3i0voZD+j1M6h=
    '''
    alphabet = "BHUPY4TaCANpsdt2zx9yXEnVkmcgl58wGbIRWSreJuKQO7fqLF3i0voZD+j1M6h="
      
    # Modify encoded string to add padding if it is not a perfectly divisible by 4
    if (len(encoded_string) % 4) != 0:
        padding = len(encoded_string)  % 4
        for i in range(padding, 4):
            encoded_string = encoded_string + "="
          
      
    padding_char = alphabet[-1]  # Last character of the alphabet is the padding character
    padding_count = encoded_string.count(padding_char)
       
    decoded_bytes = bytearray()
       
    # Iterate over the encoded string in chunks of 4 characters
    for i in range(0, len(encoded_string), 4):
        # Get the 4 characters of the chunk
        chunk = encoded_string[i:i+4]
           
        # Convert each character to its corresponding index in the alphabet
        indexes = [alphabet.index(c) for c in chunk]
           
        # Combine the indexes into a single 24-bit integer
        combined = (indexes[0] << 18) | (indexes[1] << 12) | (indexes[2] << 6) | indexes[3]
           
        # Extract the 3 bytes from the combined integer and append them to the decoded bytes
        decoded_bytes.extend([(combined >> 16) & 0xFF, (combined >> 8) & 0xFF, combined & 0xFF])
       
    # Remove the extra padding bytes if present
    if padding_count > 0:
        decoded_bytes = decoded_bytes[:-padding_count]
       
    # Return the decoded bytes as a string
    return decoded_bytes
   
def decrypt(encbuffer, xor_key_1, result_buff):
    '''
    # This "decrypt" function generates a single Byte XOR key. It gets the the length of the key, xor's that integer with the first Char of the key, take the results of that xor, and xor's with the second char, etc to get the single byte XOR key.
    # It then leverages that xor key to XOR the encrypted buffer.
    '''
    xor_key_len = len(xor_key_1)
    xor_key_len_2 = len(xor_key_1)
    if xor_key_len_2 > 0:
        count = 1
        while xor_key_len_2 > 0:
            xor_key_len ^= xor_key_1[count - 1]
            count += 1
            xor_key_len_2 -= 1
    result_buff = encbuffer
    str_len = len(encbuffer)
    str_len_copy = str_len
    if str_len > 0:
        counter = 1
        while str_len_copy > 0:
            result_buff[counter - 1] = ~(encbuffer[counter - 1] ^ xor_key_len) & 0xFF
            counter += 1
            str_len_copy -= 1
    return result_buff
 
 
 
###################################################                                                                                                         ###################################################
################################################### These functions were written by OALabs https://gist.github.com/OALabs/04ef6b2d6203d162c5b3b0eefd49530c  ###################################################
###################################################                                                                                                         ###################################################
def set_hexrays_comment(address, text):
    '''
    set comment in decompiled code
    '''
    cfunc = idaapi.decompile(address)
    tl = idaapi.treeloc_t()
    tl.ea = address
    tl.itp = idaapi.ITP_SEMI
    cfunc.set_user_cmt(tl, text)
    cfunc.save_user_cmts()
  
  
def set_comment(address, text):
    ## Set in dissassembly
    idc.set_cmt(address, text,0)
    ## Set in decompiled data
    set_hexrays_comment(address, text)
      
def get_reg_value(ptr_addr, reg_name):
    e_count = 0
    ## Just for safety only count back 500 heads
    while e_count < 500:
        e_count += 1
        ptr_addr = idc.prev_head(ptr_addr)
        if idc.print_insn_mnem(ptr_addr) == 'mov':
            if idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                tmp_reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                if reg_name.lower() == tmp_reg_name.lower():
                    if idc.get_operand_type(ptr_addr, 1) == idc.o_imm:
                        return idc.get_operand_value(ptr_addr, 1)
        elif idc.print_insn_mnem(ptr_addr) == 'pop':
            ## Match the following pattern
            ## push    3
            ## pop     edi
            if idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                tmp_reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                if reg_name.lower() == tmp_reg_name.lower():
                    ## Get prev command
                    tmp_addr = idc.prev_head(ptr_addr)
                    if idc.print_insn_mnem(tmp_addr) == 'push':
                        if idc.get_operand_type(tmp_addr, 0) == idc.o_imm:
                            reg_value = idc.get_operand_value(tmp_addr, 0)
                            return reg_value
        elif idc.print_insn_mnem(ptr_addr) == 'ret':
            ## We ran out of space in the function
            raise DecryptorError()
    ## If we got here we hit the e_count
    raise DecryptorError()
 
################################################### ###################################################
################################################### ###################################################
################################################### ###################################################
  
def read_string(address):
    '''
    # This read_string function read the string at the address provided
    '''
    string = ida_bytes.get_strlit_contents(address, -1, ida_bytes.get_full_flags(address))
    return string
          
def extract_encoded_argument(str_array, address_array):
    '''
    # This extract_encoded_argument function finds xref'd to the function within the IDB labeled "decode_custom_base64_wrap" and gathers the argument from the EAX register
    # It then extracts the string the EAX register is pointing to via calling get_reg_value and read_string
    '''
    function_name = "decode_custom_base64_wrap"
    counter = 0
    for xref in idautils.CodeRefsTo(idc.get_name_ea_simple(function_name), 0):
        call_insn = idc.prev_head(xref)
        address_array.append(xref)
        reg = get_reg_value(xref, "eax")
        str = read_string(reg)
        str_array.append(str)
        counter = counter + 1
    return counter
  
def extract_xor_argument(key_array):
    '''
    # This extract_xor_argument function finds x-ref's to the function within the IDB labled "decrypt"  and gathers the argument from the EDX register
    # It then extracts the string the EDX register is pointing to via calling get_reg_value and read_string
    '''
    function_name = "decrypt"
    for xref in idautils.CodeRefsTo(idc.get_name_ea_simple(function_name), 0):
        reg = get_reg_value(xref, "edx")
        str = read_string(reg)
        key_array.append(str)
    
  
# Main script entry point
if __name__ == "__main__":
    # Setup arrays of keys, strings, and addresses
    keys = []
    strs = []
    addresses = []
      
    # Fill arrays with args passed to the Decryption function (I.e. encrypted string and  ey)
    counter = extract_encoded_argument(strs, addresses)
    extract_xor_argument(keys)
      
    # Loop through the arrays decoding the base64 strings and implementing the xor algoirthm to decrypt the string. Output to console the encryption key, the encrypted string, and the now decrypted version of the string. 
    for i in range(0,counter):
        print("Key: " + str(keys[i]) + ", Str: " + str(strs[i]))
        decoded_arg = custom_base64_decode(strs[i].decode('utf-8'))
        decrypted = decrypt(decoded_arg, keys[i], "hold")
        print("Decrypted: " + str(decrypted))
        set_hexrays_comment(addresses[i],str(decrypted))
        set_comment(addresses[i],str(decrypted))   
