import ida_bytes
import ida_segment
import idautils
import iced_x86 # Using iced because IDAs instruction class doesn't provide enough info :upside-down-smile:


MAX_STRING_LENGTH = 512
MAX_TRACE_INSTRUCTIONS = 1500
COMMENT_PREFIX = "[decrypted-string]"

IMMEDIATE_KINDS = {
    iced_x86.OpKind.IMMEDIATE8,
    iced_x86.OpKind.IMMEDIATE16,
    iced_x86.OpKind.IMMEDIATE32,
    iced_x86.OpKind.IMMEDIATE64,
    iced_x86.OpKind.IMMEDIATE8TO16,
    iced_x86.OpKind.IMMEDIATE8TO32,
    iced_x86.OpKind.IMMEDIATE8TO64,
    iced_x86.OpKind.IMMEDIATE32TO64,
}


def decode_instruction(address):
    if not ida_bytes.is_code(ida_bytes.get_flags(address)):
        return None

    size = ida_bytes.get_item_size(address)
    if not 1 <= size <= 15:
        return None

    data = ida_bytes.get_bytes(address, size)
    if data is None:
        return None

    instruction = iced_x86.Decoder(64, data, ip=address).decode()
    if instruction.mnemonic == iced_x86.Mnemonic.INVALID or instruction.len != size:
        return None
    return instruction


def get_stack_write(instruction):
    if instruction is None or instruction.mnemonic != iced_x86.Mnemonic.MOV:
        return None
    if instruction.op0_kind != iced_x86.OpKind.MEMORY or instruction.op1_kind not in IMMEDIATE_KINDS:
        return None
    if instruction.memory_base not in (iced_x86.Register.RSP, iced_x86.Register.RBP):
        return None
    if instruction.memory_index != iced_x86.Register.NONE:
        return None

    size = iced_x86.MemorySizeExt.size(instruction.memory_size)
    if size not in (1, 2, 4, 8):
        return None

    displacement = instruction.memory_displacement
    if displacement >= (1 << 63):
        displacement -= 1 << 64

    value = instruction.immediate(1) & ((1 << (size * 8)) - 1)
    return instruction.ip, instruction.memory_base, displacement, value.to_bytes(size, "little")


def get_jump_target(instruction):
    if instruction is None or instruction.flow_control != iced_x86.FlowControl.UNCONDITIONAL_BRANCH:
        return None
    if instruction.op0_kind != iced_x86.OpKind.NEAR_BRANCH64:
        return None
    return instruction.near_branch_target


def get_frame_offset(writes):
    for previous, current in zip(writes, writes[1:]):
        _, previous_base, previous_offset, previous_data = previous
        _, current_base, current_offset, _ = current
        if previous_base == current_base:
            continue
        if previous_base == iced_x86.Register.RSP:
            return previous_offset + len(previous_data) - current_offset
        return current_offset - previous_offset - len(previous_data)
    return 0


def decode_text(data):
    if len(data) < 3:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not all(character.isprintable() or character in "\r\n\t" for character in text):
        return None
    return text


def decrypt_string(writes, length):
    if not 3 <= length <= MAX_STRING_LENGTH:
        return None

    frame_offset = get_frame_offset(writes)
    _, first_base, first_displacement, _ = writes[0]
    first_offset = first_displacement + (frame_offset if first_base == iced_x86.Register.RBP else 0)
    encoded = [None] * (length * 2)

    for address, base, displacement, data in writes:
        offset = displacement + (frame_offset if base == iced_x86.Register.RBP else 0) - first_offset
        for index, byte in enumerate(data):
            position = offset + index
            if 0 <= position < len(encoded):
                encoded[position] = byte, address

    decoded = bytearray()
    used_addresses = set()
    for index in range(length):
        first = encoded[index]
        second = encoded[index + length]
        if first is None or second is None:
            return None

        used_addresses.update((first[1], second[1]))
        byte = (first[0] - second[0]) & 0xff
        if byte == 0:
            text = decode_text(decoded)
            return (text, used_addresses) if text is not None else None
        decoded.append(byte)
    return None


def collect_and_decrypt(start_address):
    address = start_address
    visited = set()
    writes = []

    for _ in range(MAX_TRACE_INSTRUCTIONS):
        if address in visited:
            break
        visited.add(address)

        instruction = decode_instruction(address)
        if instruction is None:
            break

        write = get_stack_write(instruction)
        if write is not None:
            writes.append(write)

        length = 0
        if (instruction.mnemonic == iced_x86.Mnemonic.CMP
                and instruction.op0_kind == iced_x86.OpKind.REGISTER
                and instruction.op1_kind in IMMEDIATE_KINDS):
            length = instruction.immediate(1)

        if 3 <= length <= MAX_STRING_LENGTH and writes:
            result = decrypt_string(writes, length)
            if result is not None:
                return result

        target = get_jump_target(instruction)
        if target is not None:
            address = target
            continue
        if instruction.flow_control not in (iced_x86.FlowControl.NEXT, iced_x86.FlowControl.CONDITIONAL_BRANCH):
            break
        address += instruction.len

    total_bytes = sum(len(write[3]) for write in writes)
    if total_bytes % 2:
        return None
    return decrypt_string(writes, total_bytes // 2) if writes else None


def add_comment(address, text):
    current = ida_bytes.get_cmt(address, True) or ""
    lines = [line for line in current.splitlines() if not line.startswith(COMMENT_PREFIX)]
    lines.append(f"{COMMENT_PREFIX} {text!r}")
    ida_bytes.set_cmt(address, "\n".join(lines), True)


def find_initializers():
    initializers = {}
    for segment_address in idautils.Segments():
        segment = ida_segment.segment_info_t()
        if not ida_segment.get_segment_info(segment, segment_address):
            continue
        for address in idautils.Heads(segment.start_ea, segment.end_ea):
            write = get_stack_write(decode_instruction(address))
            if write is not None:
                initializers[address] = write

    continuations = set()
    for address, write in initializers.items():
        next_address = address + ida_bytes.get_item_size(address)
        target = get_jump_target(decode_instruction(next_address))
        if target is not None:
            next_address = target

        next_write = initializers.get(next_address)
        if next_write is None:
            continue
        if write[1] == next_write[1] and write[2] + len(write[3]) == next_write[2]:
            continuations.add(next_address)

    return sorted(initializers.keys() - continuations)


def find_and_decrypt():
    used_addresses = set()
    for address in find_initializers():
        if address in used_addresses:
            continue
        result = collect_and_decrypt(address)
        if result is None:
            continue

        text, addresses = result
        used_addresses.update(addresses)
        print(f"{address:#x} {text!r}")
        add_comment(address, text)
