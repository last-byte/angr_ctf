import angr
import claripy
import sys

def main(argv):
  path_to_binary = "./06_angr_symbolic_dynamic_memory"
  project = angr.Project(path_to_binary)

  start_address = 0x8048699
  initial_state = project.factory.blank_state(addr=start_address)

  # The binary is calling scanf("%8s %8s").
  # (!)
  password0 = claripy.BVS('password0', 64)
  password1 = claripy.BVS('password1', 64)

  # Instead of telling the binary to write to the address of the memory
  # allocated with malloc, we can simply fake an address to any unused block of
  # memory and overwrite the pointer to the data. This will point the pointer
  # with the address of pointer_to_malloc_memory_address0 to fake_heap_address.
  # Be aware, there is more than one pointer! Analyze the binary to determine
  # global location of each pointer.
  # Note: by default, Angr stores integers in memory with big-endianness. To
  # specify to use the endianness of your architecture, use the parameter
  # endness=project.arch.memory_endness. On x86, this is little-endian.
  # (!)
  fake_heap_address0 = 0xffffc93c # random address in main's stack frame
  pointer_to_malloc_memory_address0 = 0xabcc8a4 # address of buffer0 pointer
  fake_heap_address1 = 0xffffc94c # random address in main's stack frame
  pointer_to_malloc_memory_address1 = 0xabcc8ac # address of buffer1 pointer
  initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
  initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)

  # Store our symbolic values at our fake_heap_address. Look at the binary to
  # determine the offsets from the fake_heap_address where scanf writes.
  # (!)
  initial_state.memory.store(fake_heap_address0, password0)
  initial_state.memory.store(fake_heap_address1, password1)
  

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Good Job.\n' in stdout_output:
      return True
    else: return False

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Try again.\n' in stdout_output:
      return True
    else: return False

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.solver.eval(password0, cast_to=bytes)
    solution1 = solution_state.solver.eval(password1, cast_to=bytes)

    print("[+] Success! Solution is: {0} {1}".format(solution0.decode('utf-8'), solution1.decode('utf-8')))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
